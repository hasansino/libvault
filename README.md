# libvault

Retrieve secrets from vault in runtime.

Features:
* Logging with `slog` compatible logger
* Token, role, and k8 service account auth methods

## Installation

```bash
~ $ go get github.com/hasansino/libvault
```

## Example

### Token authentication (for local development)

```go
package main

import (
	"fmt"
	"log"

	"github.com/hasansino/libvault"
)

func main() {
	vaultClient, err := libvault.New("localhost:8080")
	if err != nil {
		log.Fatal(err)
	}
	
	err = vaultClient.TokenAuth("token")
	if err != nil {
		log.Fatal(err)
	}

	secret, err := vaultClient.Retrieve("secrets/auth")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%v", secret) // return type is map[string]interface{}
}
```

### AppRole authentication

```go
package main

import (
	"fmt"
	"log"

	"github.com/hasansino/libvault"
)

func main() {
	vaultClient, err := libvault.New("localhost:8080")
	if err != nil {
		log.Fatal(err)
	}

	vaultClient.SetNamespace("k8-main") // optional

	err = vaultClient.AppRoleAuth("test-role", "secret-id")
	if err != nil {
		log.Fatal(err)
	}

	secret, err := vaultClient.Retrieve("secrets/auth")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%v", secret) // return type is map[string]interface{}
}
```

### Kubernetes authentication

```go
package main

import (
	"fmt"
	"log"

	"github.com/hasansino/libvault"
)

func main() {
	vaultClient, err := libvault.New("localhost:8080")
	if err != nil {
		log.Fatal(err)
	}

	vaultClient.SetNamespace("k8-main") // optional

	err = vaultClient.K8Auth(
		"k8-role-name",
		"kubernetes",
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
	)
	if err != nil {
		log.Fatal(err)
	}

	secret, err := vaultClient.Retrieve("secrets/auth")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%v", secret) // return type is map[string]interface{}
}
```