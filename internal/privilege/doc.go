// Package privilege provides Windows privilege detection utilities.
//
// Used to gate functionality that requires elevated (Administrator) privileges,
// such as ETW session creation, without hard-blocking the entire application.
package privilege
