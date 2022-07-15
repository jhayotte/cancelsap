package main

import (
	"fmt"
	"github.com/urfave/cli"
	"github.com/jhayotte/cancelsap/authentication"
)


func main() {
	app := cli.NewApp()
	app.Name = path.Base(os.Args[0])
	app.Usage = "Cancel SAP GR and Valued MVT"
	app.Flags = commonFlags()
	app.Action = start

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func start(c *cli.Context) {
	// Context
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// SSO objects for SA client to use Keycloak to authenticate fo outgoing calls
	ssoClientCreds := &authentication.SSOCredentials{
		AuthURL:  c.String("sso-auth-url"),
		ClientID: c.String("sso-client-id"),
		Realm:    "vpgrp",
		Secret:   c.String("sso-vpgrp-secret"),
	}
	keycloakClient := authentication.NewKeycloakServer(ssoClientCreds)
}
