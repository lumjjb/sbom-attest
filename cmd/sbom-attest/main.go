// Copyright 2022 SLSA Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"
	"os"

	// TODO: Allow use of other OIDC providers?
	// Enable the github OIDC auth provider.
	_ "github.com/sigstore/cosign/pkg/providers/github"

	"github.com/spf13/cobra"
)

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "intoto-generate",
		Short: "Create and upload custom intoto attestations for Github Actions",
		Long:  "Generate custom intoto attestations for Github Actions.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("expected command")
		},
	}
	c.AddCommand(versionCmd())
	c.AddCommand(attestCmd())
	return c
}

func main() {
	check(rootCmd().Execute())
}
