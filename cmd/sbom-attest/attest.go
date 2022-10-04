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
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsav02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/spf13/cobra"

	"github.com/lumjjb/sbom-attest/pkg/signing"
	"github.com/slsa-framework/slsa-github-generator/github"
	"github.com/slsa-framework/slsa-github-generator/signing/sigstore"
)

var (
	// shaCheck verifies a hash is has only hexidecimal digits and is 64
	// characters long.
	shaCheck = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

	// wsSplit is used to split lines in the subjects input.
	wsSplit = regexp.MustCompile(`[\t ]`)
)

// parseSubjects parses the value given to the subjects option.
func parseSubjects(subjectsStr string) ([]intoto.Subject, error) {
	var parsed []intoto.Subject

	scanner := bufio.NewScanner(strings.NewReader(subjectsStr))
	for scanner.Scan() {
		// Split by whitespace, and get values.
		parts := wsSplit.Split(strings.TrimSpace(scanner.Text()), 2)

		// Lowercase the sha digest to comply with the SLSA spec.
		shaDigest := strings.ToLower(strings.TrimSpace(parts[0]))
		if shaDigest == "" {
			// Ignore empty lines.
			continue
		}
		// Do a sanity check on the SHA to make sure it's a proper hex digest.
		if !shaCheck.MatchString(shaDigest) {
			return nil, fmt.Errorf("unexpected sha256 hash %q", shaDigest)
		}

		// Check for the subject name.
		if len(parts) == 1 {
			return nil, fmt.Errorf("expected subject name for hash %q", shaDigest)
		}
		name := strings.TrimSpace(parts[1])

		for _, p := range parsed {
			if p.Name == name {
				return nil, fmt.Errorf("duplicate subject: %q", name)
			}
		}

		parsed = append(parsed, intoto.Subject{
			Name: name,
			Digest: slsav02.DigestSet{
				"sha256": shaDigest,
			},
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return parsed, nil
}

func getFile(path string) (io.Writer, error) {
	if path == "-" {
		return os.Stdout, nil
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0600)
}

// attestCmd returns the 'attest' command.
func attestCmd() *cobra.Command {
	var (
		attPath                  string
		subjects                 string
		predicateFile            string
		predicateType            string
		sbomFile                 string
		sbomSha256               string
		sbomUri                  string
		artifactRepo             string
		artifactRepoCommit       string
		attestationGenRepo       string
		attestationGenRepoCommit string
		local                    bool
	)

	c := &cobra.Command{
		Use:   "attest",
		Short: "Create and upload a signed SLSA attestation",
		Long: `Generate and sign SLSA provenance to form an attestation and upload to a 
Rekor transparency log. This command assumes that it is being run in 
the context of a Github Actions workflow unless the --local flag is provided.`,

		Run: func(cmd *cobra.Command, args []string) {
			/*
				ghContext, err := github.GetWorkflowContext()
				check(err)
			*/

			parsedSubjects, err := parseSubjects(subjects)
			check(err)

			if len(parsedSubjects) == 0 {
				check(errors.New("expected at least one subject"))
			}

			ctx := context.Background()

			/*
				audience := regexp.MustCompile(`^(https?://)?github\.com/?`).ReplaceAllString("https://github.com/slsa-framework/slsa-github-generator@v1", "")
				_, err = c.Token(ctx, []string{audience})
				check(err)
			*/

			var p *intoto.Statement
			if sbomFile != "" || sbomSha256 != "" || sbomUri != "" {
				sboms, err := parseSbomInput(sbomFile, sbomUri, sbomSha256)
				check(err)

				metadata, err := createSbomMetadata(artifactRepo, artifactRepoCommit, attestationGenRepo, attestationGenRepoCommit)
				check(err)

				p, err = CustomSbomStatement(parsedSubjects, predicateType, sboms, metadata)
			} else {
				predicateBytes, err := os.ReadFile(predicateFile)
				check(err)

				var genericPredicate map[string]interface{}
				err = json.Unmarshal(predicateBytes, &genericPredicate)
				check(err)

				p, err = CustomIntotoStatement(parsedSubjects, predicateType, genericPredicate)
			}
			check(err)

			var att signing.Attestation

			if local {
				s := signing.NewDefaultFulcio()
				att, err = s.Sign(ctx, p)
			} else {
				_, err = github.NewOIDCClient()
				check(err)

				s := sigstore.NewDefaultFulcio()
				att, err = s.Sign(ctx, p)
			}
			check(err)

			r := sigstore.NewDefaultRekor()
			_, err = r.Upload(ctx, att)
			check(err)

			if attPath != "" {
				f, err := getFile(attPath)
				check(err)

				_, err = f.Write(att.Bytes())
				check(err)

			}
		},
	}

	c.Flags().StringVarP(&attPath, "signature", "g", "attestation.intoto.jsonl", "Path to write the signed attestation")
	c.Flags().StringVarP(&subjects, "subjects", "s", "", "Formatted list of subjects in the same format as sha256sum")
	c.Flags().StringVarP(&predicateType, "predicateType", "t", "", "Predicate type for intoto statement header")
	c.Flags().StringVarP(&predicateFile, "predicateFile", "f", "predicate.json", "Path to retrieve custom predicate to create attestation from")
	// Pass in SBOM file OR the sha256 and the sbomURI
	c.Flags().StringVarP(&sbomFile, "sbom", "b", "", "Path to create SBOM predicate")
	c.Flags().StringVarP(&sbomSha256, "sbomSha256", "d", "", "Sha256 hash the SBOM")
	c.Flags().StringVarP(&sbomUri, "sbomUri", "u", "", "SBOM Uri if file not provided")
	c.Flags().StringVarP(&artifactRepo, "art-repo", "a", "NoAssertion", "Github repository from which the artifact was built")
	c.Flags().StringVarP(&artifactRepoCommit, "art-repo-commit", "c", "NoAssertion", "Commit of repository from which the artifact was built")
	c.Flags().StringVarP(&attestationGenRepo, "att-generation-repo", "x", "NoAssertion", "Github repository used to generate the attestation")
	c.Flags().StringVarP(&attestationGenRepoCommit, "att-generation-repo-commit", "y", "NoAssertion", "Commit of Github repository used to generate the attestation")
	c.Flags().BoolVarP(&local, "local", "l", false, "Whether attest will run in a GH action or locally")

	return c
}

type SBOMPredicate struct {
	Sboms         []SbomDocument `json:"sboms"`
	BuildMetadata SbomMetadata   `json:"build-metadata"`
}

type SbomMetadata struct {
	ArtifactSourceRepo       string `json:"artifact-source-repo"`
	ArtifactSourceRepoCommit string `json:"artifact-source-repo-commit"`
	AttestationGenRepo       string `json:"attestation-generator-repo"`
	AttestationGenRepoCommit string `json:"attestation-generator-repo-commit"`
	// Consider adding SPDXID, SBOM name for cases where SBOM content cannot be accessed
}

// CustomSbomStatement creates an intoto SBOM statement with provided fields
// Take in SBOM hash, URI,
func CustomSbomStatement(subjects []intoto.Subject, predicateType string, docs []SbomDocument, metadata SbomMetadata) (*intoto.Statement, error) {
	return &intoto.Statement{
		StatementHeader: intoto.StatementHeader{
			Type:          intoto.StatementInTotoV01,
			PredicateType: predicateType,
			Subject:       subjects,
		},
		Predicate: SBOMPredicate{
			Sboms:         docs,
			BuildMetadata: metadata,
		},
	}, nil
}

// CustomIntotoStatement creates an intoto statement with provided fields
func CustomIntotoStatement(subjects []intoto.Subject, predicateType string, predicate interface{}) (*intoto.Statement, error) {

	return &intoto.Statement{
		StatementHeader: intoto.StatementHeader{
			Type:          intoto.StatementInTotoV01,
			PredicateType: predicateType,
			Subject:       subjects,
		},
		Predicate: predicate,
	}, nil
}

func createSbomMetadata(artifactRepo string, artifactRepoCommit string, attestationGenRepo string, attestationGenRepoCommit string) (SbomMetadata, error) {
	return SbomMetadata{
		ArtifactSourceRepo:       artifactRepo,
		ArtifactSourceRepoCommit: artifactRepoCommit,
		AttestationGenRepo:       attestationGenRepo,
		AttestationGenRepoCommit: attestationGenRepoCommit,
	}, nil
}

type SbomDocument struct {
	// SPDX, CycloneDX, etc.
	Format string `json:"format"`
	// Digest of document
	Digest slsav02.DigestSet `json:"digest"`
	// Uri to download document
	Uri string `json:"uri"`
	// Bytes of document (optional, alternative to Uri)
	Bytes []byte `json:"bytes,omitempty"`
}

func parseSbomInput(sbomFile string, sbomUri string, sbomSha256 string) ([]SbomDocument, error) {
	if sbomFile != "" {
		sbomBytes, err := os.ReadFile(sbomFile)
		if err != nil {
			return nil, err
		}

		sum256 := fmt.Sprintf("%x", sha256.Sum256(sbomBytes))

		return []SbomDocument{{
			Format: "SPDX",
			Digest: slsav02.DigestSet{
				"sha256": sum256,
			},
			Bytes: sbomBytes,
		}}, nil
	}

	// TODO: Maybe allow downloading and hashing?
	if sbomUri != "" && sbomSha256 != "" {
		return []SbomDocument{{
			Format: "SPDX",
			Digest: slsav02.DigestSet{
				"sha256": sbomSha256,
			},
			Uri: sbomUri,
		}}, nil
	}

	return nil, fmt.Errorf("insufficient information to create SBOM attestation")
}
