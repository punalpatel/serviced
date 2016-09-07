// Copyright 2016 The Serviced Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import "crypto"

var (
	// Verify JWTIdentity implements the Identity interface
	_ Identity   = &jwtIdentity{}
	_ jwt.Claims = &jwtIdentity{}
)

// jwtIdentity is an implementation of the Identity interface based on a JSON
// web token.
type jwtIdentity struct {
	Host        string `json:"hid,omitempty"`
	Pool        string `json:"pid,omitempty"`
	ExpiresAt   int64  `json:"exp,omitempty"`
	IssuedAt    int64  `json:"iat,omitempty"`
	AdminAccess bool   `json:"adm,omitempty"`
	DFSAccess   bool   `json:"dfs,omitempty"`
	PubKey      string `json:"key,omitempty"`
}

func ParseJWTIdentity(token string, keystore KeyStore) Identity {
	token, err := jwt.ParseWithClaims(token, &jwtIdentity{}, func(token *jwt.Token) {
		// Validate the algorithm matches the keystore
	})
}

func (id *jwtIdentity) Valid() error {

}

func (id *jwtIdentity) Expired() bool {

}

func (id *jwtIdentity) HostID() string {

}

func (id *jwtIdentity) PoolID() string {

}

func (id *jwtIdentity) HasAdminAccess() bool {

}

func (id *jwtIdentity) HasDFSAccess() bool {

}

func (id *jwtIdentity) PublicKey() crypto.PublicKey {

}
