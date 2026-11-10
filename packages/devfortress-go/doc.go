// Package devfortress is the DevFortress event reporting client for Go
// (external mode). It queues security events in memory and delivers them in
// batches to the DevFortress platform; every request is signed with the
// request signature contract (see Signer): the API key never goes on the
// wire, only a non-secret key ID does.
//
// Delivery never panics or returns an error into the host application: a
// failed delivery comes back as a DeliveryResult from Flush and is logged.
// Only a missing API key fails construction.
//
// The standard library is the only dependency. Framework adapters (such as
// the nested gin module) build on this package without changing the signing
// or delivery behaviour.
package devfortress
