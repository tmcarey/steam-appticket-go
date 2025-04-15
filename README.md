# Go Steam App Ticket Parser

Updated to support version 2.0 of the app ticket format.

This module allows you to authenticate steam users on your Go backend.

Basically a transpilation of
[DoctorMckay's excellent node implementation](https://github.com/DoctorMcKay/node-steam-appticket).

## Usage

### ParseEncryptedAppTicket (ticket, key)

- `ticket` - `[]byte` encrypted ticket data
- `key` - `[]byte` key data

Usually you get the ticket in base64 format and the key in hex format from
Steam, you will need to decode both first.

If you are using encrypted app tickets you can ignore signature verification,
since the encryption step validates the ticket.

```go
import (
  "github.com/tmcarey/steam-appticket-go"
  "encoding/base64"
  "encoding/hex"
)

ticket := base64.DecodeString('<TICKET>');
key := hex.DecodeString('<KEY>');

/* Returns a SteamAppTicket */
app_ticket, err := steamappticket.ParseEncryptedAppTicket(ticket, decryptionKey)
```

### ParseAppTicket (ticket, key)

- `ticket` - `[]byte` encrypted ticket data
- `allowInvalidSignature` - `bool` whether or not to error if the signature is
  invalid

```go
import (
  "github.com/tmcarey/steam-appticket-go"
  "encoding/base64"
)

ticket := base64.DecodeString('<TICKET>');

/* Returns a SteamAppTicket */
app_ticket, err := steamappticket.ParseAppTicket(ticket, false)
```

## SteamAppTicket struct

- `AuthTicket []byte`: The raw authentication ticket for the app.
- `SteamID uint64`: The Steam ID of the user who owns the ticket.
- `GCToken uint64`: The game connect token for the app.
- `GCTokenGenerated time.Time`: The time when the ticket was generated.
- `SessionExternalIP net.IP`: The external IP address of the user's session.
- `ClientConnectionTime uint32`: The time when the client connected to the
  server.
- `ClientConnectionCount uint32`: The number of times the client has connected
  to the server.
- `Version uint32`: The version of the app.
- `AppID uint32`: The game's Steam App ID.
- `OwnershipTicketExternalIP net.IP`: The external IP address of the user's
  ownership ticket.
- `OwnershipTicketInternalIP net.IP`: The internal IP address of the user's
  ownership ticket.
- `OwnershipFlags uint32`: Flags associated with the ownership ticket.
- `OwnershipTicketGenerated time.Time`: The time when the ownership ticket was
  generated.
- `OwnershipTicketExpires time.Time`: The time when the ownership ticket
  expires.
- `Licenses []uint32`: A list of the user's licenses for the app.
- `DLC []DLCDetails`: A list of details about the DLCs which the account holds.
- `Signature []byte`: The signature of the ticket.
- `IsExpired bool`: Indicates whether the ticket has expired.
- `HasValidSignature bool`: Indicates whether the ticket has a valid signature.
- `IsValid bool`: Indicates whether the ticket is valid (neither expired nor
  with an invalid signature).
- `UserData []byte`: Additional user data associated with the ticket, created
  when requesting the ticket.

### DLCDetails

- `AppID    uint32`: The DLC's App ID
- `Licenses []uint32`: Package IDs of all the licenses which give the owner
  access to this DLC

You can read more info about how app tickets work
[here](https://github.com/DoctorMcKay/node-steam-user/wiki/Steam-App-Auth).
