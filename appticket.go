package steamappticket

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"hash/crc32"
	"io"
	"net"
	"time"

	"github.com/tmcarey/steam-appticket-go/generated/github.com/tmcarey/steam-appticket-go/protobufs/steamencryptedappticket"
	"google.golang.org/protobuf/proto"
)

// SteamID represents a Steam identifier
type SteamID uint64

// AppOwnershipTicket contains ownership information for a Steam application
type AppOwnershipTicket struct {
	Version                   uint32    `json:"version"`
	SteamID                   SteamID   `json:"steamID"`
	AppID                     uint32    `json:"appID"`
	OwnershipTicketExternalIP net.IP    `json:"ownershipTicketExternalIP"`
	OwnershipTicketInternalIP net.IP    `json:"ownershipTicketInternalIP"`
	OwnershipFlags            uint32    `json:"ownershipFlags"`
	OwnershipTicketGenerated  time.Time `json:"ownershipTicketGenerated"`
	OwnershipTicketExpires    time.Time `json:"ownershipTicketExpires"`
	Licenses                  []uint32  `json:"licenses"`
	DLC                       []DLCInfo `json:"dlc"`
	Signature                 []byte    `json:"signature,omitempty"`
	IsExpired                 bool      `json:"isExpired"`
	HasValidSignature         bool      `json:"hasValidSignature"`
	IsValid                   bool      `json:"isValid"`
}

// DLCInfo contains information about downloadable content
type DLCInfo struct {
	AppID    uint32   `json:"appID"`
	Licenses []uint32 `json:"licenses"`
}

// AppTicket extends AppOwnershipTicket with authentication information
type AppTicket struct {
	AppOwnershipTicket
	AuthTicket            []byte    `json:"authTicket"`
	GCToken               string    `json:"gcToken"`
	TokenGenerated        time.Time `json:"tokenGenerated"`
	SessionExternalIP     net.IP    `json:"sessionExternalIP"`
	ClientConnectionTime  uint32    `json:"clientConnectionTime"`
	ClientConnectionCount uint32    `json:"clientConnectionCount"`
}

// DecodedEncryptedAppTicket represents a decoded encrypted application ticket
type DecodedEncryptedAppTicket struct {
	Version                   uint32    `json:"version"`
	SteamID                   SteamID   `json:"steamID"`
	AppID                     uint32    `json:"appID"`
	OwnershipTicketExternalIP string    `json:"ownershipTicketExternalIP"`
	OwnershipTicketInternalIP string    `json:"ownershipTicketInternalIP"`
	OwnershipFlags            uint32    `json:"ownershipFlags"`
	OwnershipTicketGenerated  time.Time `json:"ownershipTicketGenerated"`
	Licenses                  []uint32  `json:"licenses"`
	DLC                       []DLCInfo `json:"dlc"`
	UserData                  []byte    `json:"userData"`
	Unknown2                  uint64    `json:"unknown2"`
	Unknown3                  uint64    `json:"unknown3"`
	Unknown4                  uint32    `json:"unknown4"`
}

type SteamAppTicketError struct {
	Message string
}

func (e *SteamAppTicketError) Error() string {
	return e.Message
}

var InvalidTicketError error = &SteamAppTicketError{Message: "Invalid ticket"}
var InvalidSignatureError error = &SteamAppTicketError{Message: "Missing or Invalid Signature"}
var DecryptionFailedError error = &SteamAppTicketError{Message: "Failed to decrypt ticket"}

var SteamPublicKey, _ = pem.Decode([]byte(
	`-----BEGIN PUBLIC KEY-----
MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDf7BrWLBBmLBc1OhSwfFkRf53T
2Ct64+AVzRkeRuh7h3SiGEYxqQMUeYKO6UWiSRKpI2hzic9pobFhRr3Bvr/WARvY
gdTckPv+T1JzZsuVcNfFjrocejN1oWI0Rrtgt4Bo+hOneoo3S57G9F1fOpn5nsQ6
6WOiu4gZKODnFMBCiQIBEQ==
-----END PUBLIC KEY-----`))

func padPKCS7(data []byte, blockSize int) []byte {
	rem := len(data) % blockSize

	if rem == 0 {
		return data
	}

	padSize := blockSize - rem

	pad := make([]byte, padSize)
	for i := 0; i < padSize; i++ {
		pad[i] = byte(padSize)
	}

	return append(data, pad...)
}

func unpadPKCS7(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty input")
	}
	if len(data)%blockSize != 0 {
		return nil, errors.New("input is not a multiple of the block size")
	}
	padSize := int(data[len(data)-1])
	if padSize == 0 || padSize > blockSize {
		return nil, errors.New("invalid padding size")
	}
	for i := len(data) - padSize; i < len(data); i++ {
		if data[i] != byte(padSize) {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-padSize], nil
}

func symmetricDecrypt(input []byte, key []byte, checkHmac bool) (decrypted []byte, error error) {
	ivBlock, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	// The IV is the first 16 bytes of the input
	// Decrypt only works in blocks of 16, but since we are exactly 16 we can just run it once
	iv := input[:16]
	ivBlock.Decrypt(iv, iv)

	dataBlock := cipher.NewCBCDecrypter(ivBlock, iv)

	decrypted = padPKCS7(input[16:], 16)

	dataBlock.CryptBlocks(decrypted, decrypted)

	decrypted, err = unpadPKCS7(decrypted, 16)

	if err != nil {
		return nil, err
	}

	if checkHmac {
		// The last 3 bytes of the IV are a random value, and the remainder are a partial HMAC
		var remotePartialHmac = iv[:len(iv)-3]
		var random = iv[len(iv)-3:]
		var mac = hmac.New(sha1.New, key[:16])
		mac.Write(random)
		mac.Write(decrypted)
		expectedHmac := mac.Sum(nil)
		if !hmac.Equal(remotePartialHmac, expectedHmac) {
			return nil, InvalidTicketError
		}
	}

	return decrypted, nil
}

/**
 *
 * @param {[]byte} ticket - The raw encrypted ticket
 * @param {[]byte|string} encryptionKey - The raw encryption key
 * @returns {SteamAppTicket}
 */
func ParseEncryptedAppTicket(ticket []byte, key []byte) (*DecodedEncryptedAppTicket, error) {
	app_ticket := &steamencryptedappticket.EncryptedAppTicket{}

	if err := proto.Unmarshal(ticket, app_ticket); err != nil {
		return nil, err
	}

	// we decrypt in place, so the encrypted ticket is the same as the decrypted ticket after this
	decrypted, err := symmetricDecrypt(app_ticket.GetEncryptedTicket(), key, false)

	if err != nil {
		return nil, DecryptionFailedError
	}

	if crc32.ChecksumIEEE(decrypted) != app_ticket.CrcEncryptedticket {
		return nil, InvalidTicketError
	}
	encryptedUserDataCount := app_ticket.GetCbEncrypteduserdata()

	ownershipTicketLength := binary.LittleEndian.Uint32(decrypted[encryptedUserDataCount : encryptedUserDataCount+4])

	ownershipTicket, err := ParseAppTicket(decrypted[encryptedUserDataCount:encryptedUserDataCount+ownershipTicketLength], true)

	if err != nil {
		return nil, err
	}

	decodedTicket := &DecodedEncryptedAppTicket{
		Version:                   ownershipTicket.Version,
		SteamID:                   ownershipTicket.SteamID,
		AppID:                     ownershipTicket.AppID,
		OwnershipTicketExternalIP: ownershipTicket.OwnershipTicketExternalIP.String(),
		OwnershipTicketInternalIP: ownershipTicket.OwnershipTicketInternalIP.String(),
		OwnershipFlags:            ownershipTicket.OwnershipFlags,
		OwnershipTicketGenerated:  ownershipTicket.OwnershipTicketGenerated,
		Licenses:                  ownershipTicket.Licenses,
		DLC:                       ownershipTicket.DLC,
	}

	// the beginning is the user-supplied data
	userData := decrypted[0:app_ticket.GetCbEncrypteduserdata()]

	decodedTicket.UserData = userData

	remainderOffset := 0
	if app_ticket.TicketVersionNo == 2 {
		remainderOffset += 8 + 8 + 4
		readOffset := app_ticket.CbEncrypteduserdata + ownershipTicketLength

		// Read Unknown2 (uint64)
		unknown2 := binary.LittleEndian.Uint64(decrypted[readOffset:])
		decodedTicket.Unknown2 = unknown2
		readOffset += 8

		// Read Unknown3 (uint64)
		unknown3 := binary.LittleEndian.Uint64(decrypted[readOffset:])
		decodedTicket.Unknown3 = unknown3
		readOffset += 8

		// Read Unknown4 (uint32)
		decodedTicket.Unknown4 = binary.LittleEndian.Uint32(decrypted[readOffset:])
	}

	remainder := decrypted[app_ticket.GetCbEncrypteduserdata()+ownershipTicketLength+uint32(remainderOffset):]

	if len(remainder) >= 8+20 {
		// salted sha1 hash, next 8 bytes are salt
		dataToHash := decrypted[:app_ticket.GetCbEncrypteduserdata()+ownershipTicketLength+uint32(remainderOffset)]

		salt := remainder[:8]
		hash := remainder[8:28]

		hasher := sha1.New()
		hasher.Write(dataToHash)
		hasher.Write(salt)

		if !bytes.Equal(hash, hasher.Sum(nil)) {
			return nil, InvalidTicketError
		}
	}

	return decodedTicket, nil
}

func verifySignature(data []byte, signature []byte) error {
	rsaKey, err := x509.ParsePKIXPublicKey(SteamPublicKey.Bytes)

	if err != nil {
		return err
	}

	pubKey := rsaKey.(*rsa.PublicKey)

	hash := sha1.Sum(data)

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA1, hash[:], signature)

	return err
}

/**
 *
 * @param {[]byte} ticket - The raw encrypted ticket
 * @param {bool} allowInvalidSignature - Whether to error on tickets with invalid signatures
 * @returns {SteamAppTicket}
 */
func ParseAppTicket(ticket []byte, allowInvalidSignature bool) (*AppTicket, error) {
	buf := bytes.NewReader(ticket)
	details := &AppTicket{}
	var initialLength uint32

	err := binary.Read(buf, binary.LittleEndian, &initialLength)
	if err != nil {
		return nil, InvalidTicketError
	}

	if initialLength == 20 {
		// This is a full appticket, with a GC token and session header (in addition to ownership ticket)
		details.AuthTicket = make([]byte, 52)
		copy(details.AuthTicket, ticket[:52])

		err = binary.Read(buf, binary.LittleEndian, &details.GCToken)

		if err != nil {
			return nil, InvalidTicketError
		}

		_, err = buf.Seek(8, 1) // the SteamID gets read later on

		if err != nil {
			return nil, InvalidTicketError
		}

		var tokenGenerated uint32

		err = binary.Read(buf, binary.LittleEndian, &tokenGenerated)

		if err != nil {
			return nil, InvalidTicketError
		}

		details.TokenGenerated = time.Unix(int64(tokenGenerated), 0)

		var sessionHeaderLength uint32
		err = binary.Read(buf, binary.LittleEndian, &sessionHeaderLength)

		if err != nil {
			return nil, InvalidTicketError
		}

		if sessionHeaderLength != 24 {
			return nil, InvalidTicketError
		}

		_, err = buf.Seek(8, 1) // filler

		if err != nil {
			return nil, InvalidTicketError
		}

		var sessionExternalIP uint32
		err = binary.Read(buf, binary.LittleEndian, &sessionExternalIP)

		if err != nil {
			return nil, InvalidTicketError
		}

		details.SessionExternalIP = make(net.IP, 4)
		binary.LittleEndian.PutUint32(details.SessionExternalIP, sessionExternalIP)

		_, err = buf.Seek(4, 1) // filler

		if err != nil {
			return nil, InvalidTicketError
		}

		err = binary.Read(buf, binary.LittleEndian, &details.ClientConnectionTime)

		if err != nil {
			return nil, InvalidTicketError
		}
		err = binary.Read(buf, binary.LittleEndian, &details.ClientConnectionCount)

		if err != nil {
			return nil, InvalidTicketError
		}

		var ownershipSectionWithSignatureLength uint32
		err = binary.Read(buf, binary.LittleEndian, &ownershipSectionWithSignatureLength)

		if err != nil {
			return nil, InvalidTicketError
		}
		if int(ownershipSectionWithSignatureLength)+buf.Len() != int(buf.Size()) {
			return nil, InvalidTicketError
		}
	} else {
		_, err = buf.Seek(-4, 1)

		if err != nil {
			return nil, InvalidTicketError
		}
	}

	ownershipTicketOffset, err := buf.Seek(0, io.SeekCurrent)

	if err != nil {
		return nil, InvalidTicketError
	}

	var ownershipTicketLength uint32
	err = binary.Read(buf, binary.LittleEndian, &ownershipTicketLength)

	if err != nil {
		return nil, InvalidTicketError
	}

	if int(ownershipTicketLength) != len(ticket) && int(ownershipTicketLength)+128 != buf.Len() {
		return nil, InvalidTicketError
	}

	err = binary.Read(buf, binary.LittleEndian, &details.Version)

	if err != nil {
		return nil, InvalidTicketError
	}
	err = binary.Read(buf, binary.LittleEndian, &details.SteamID)

	if err != nil {
		return nil, InvalidTicketError
	}
	err = binary.Read(buf, binary.LittleEndian, &details.AppID)

	if err != nil {
		return nil, InvalidTicketError
	}

	var ownershipTicketExternalIP, ownershipTicketInternalIP uint32
	err = binary.Read(buf, binary.LittleEndian, &ownershipTicketExternalIP)

	if err != nil {
		return nil, InvalidTicketError
	}
	err = binary.Read(buf, binary.LittleEndian, &ownershipTicketInternalIP)

	if err != nil {
		return nil, InvalidTicketError
	}
	details.OwnershipTicketExternalIP = make(net.IP, 4)
	details.OwnershipTicketInternalIP = make(net.IP, 4)
	binary.LittleEndian.PutUint32(details.OwnershipTicketExternalIP, ownershipTicketExternalIP)
	binary.LittleEndian.PutUint32(details.OwnershipTicketInternalIP, ownershipTicketInternalIP)

	err = binary.Read(buf, binary.LittleEndian, &details.OwnershipFlags)

	if err != nil {
		return nil, InvalidTicketError
	}

	var ownershipTicketGenerated, ownershipTicketExpires uint32
	err = binary.Read(buf, binary.LittleEndian, &ownershipTicketGenerated)

	if err != nil {
		return nil, InvalidTicketError
	}
	err = binary.Read(buf, binary.LittleEndian, &ownershipTicketExpires)

	if err != nil {
		return nil, InvalidTicketError
	}
	details.OwnershipTicketGenerated = time.Unix(int64(ownershipTicketGenerated), 0)
	details.OwnershipTicketExpires = time.Unix(int64(ownershipTicketExpires), 0)

	var licenseCount uint16
	err = binary.Read(buf, binary.LittleEndian, &licenseCount)

	if err != nil {
		return nil, InvalidTicketError
	}

	details.Licenses = make([]uint32, licenseCount)
	for i := 0; i < int(licenseCount); i++ {
		err = binary.Read(buf, binary.LittleEndian, &details.Licenses[i])

		if err != nil {
			return nil, InvalidTicketError
		}
	}

	var dlcCount uint16
	err = binary.Read(buf, binary.LittleEndian, &dlcCount)

	if err != nil {
		return nil, InvalidTicketError
	}

	details.DLC = make([]DLCInfo, dlcCount)
	for i := 0; i < int(dlcCount); i++ {
		dlc := DLCInfo{}
		err = binary.Read(buf, binary.LittleEndian, &dlc.AppID)

		if err != nil {
			return nil, InvalidTicketError
		}

		var dlcLicenseCount uint16
		err = binary.Read(buf, binary.LittleEndian, &dlcLicenseCount)

		if err != nil {
			return nil, InvalidTicketError
		}

		dlc.Licenses = make([]uint32, dlcLicenseCount)
		for j := 0; j < int(dlcLicenseCount); j++ {
			err = binary.Read(buf, binary.LittleEndian, &dlc.Licenses[j])

			if err != nil {
				return nil, InvalidTicketError
			}
		}

		details.DLC[i] = dlc
	}

	_, err = buf.Seek(2, 1) // reserved

	if err != nil {
		return nil, InvalidTicketError
	}

	hasSignature := false

	if buf.Len() == 128 {
		hasSignature = true

		details.Signature = make([]byte, 128)
		_, err = buf.Read(details.Signature)

		if err != nil {
			return nil, InvalidSignatureError
		}
	}

	details.IsExpired = time.Now().After(details.OwnershipTicketExpires)
	details.HasValidSignature = hasSignature && verifySignature(ticket[ownershipTicketOffset:uint32(ownershipTicketOffset)+ownershipTicketLength], details.Signature) == nil
	details.IsValid = !details.IsExpired && (details.Signature == nil || details.HasValidSignature)

	if !allowInvalidSignature && !details.HasValidSignature {
		return nil, InvalidSignatureError
	}

	return details, nil
}
