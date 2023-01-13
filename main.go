package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/gocarina/gocsv"
)

func main() {
	var imagesFlag string
	flag.StringVar(&imagesFlag, "images", "", "space separated image names")

	flag.Parse()

	if imagesFlag == "" {
		flag.Usage()
		os.Exit(0)
	}

	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}
	defer cli.Close()

	images := strings.Split(imagesFlag, " ")
	for _, image := range images {
		if err := PullImage(ctx, cli, image); err != nil {
			log.Println("error pulling image: ", err)
			os.Exit(1)
		}

		if err := ScanImage(image); err != nil {
			log.Println("error scanning image:  ", err)
			os.Exit(1)
		}
	}
	if err := PrepareResult(); err != nil {
		log.Println("error: ", err)
	}
}

func PrepareResult() error {
	entry, _ := os.ReadDir("./tykio")

	var rx []ResultRow
	var cveIdx []string
	for _, file := range entry {
		dest := "./tykio/" + file.Name()
		f, err := os.Open(dest)
		if err != nil {
			log.Println("error opening file: ", f)
			return err
		}
		defer f.Close()

		fbytes, err := io.ReadAll(f)
		if err != nil {
			log.Println("reading bytes error")
			return err
		}

		var s SnykDTO
		if err := json.Unmarshal(fbytes, &s); err != nil {
			log.Println("error unmarshalling to struct")
			return err
		}

		for _, vuln := range s.Vulnerabilities {
			var rr ResultRow
			cveId := vuln.ID
			for i, id := range cveIdx {
				if id == cveId {
					if !strings.Contains(rx[i].Source, vuln.From[0]) {
						add := ", " + vuln.From[0]
						rx[i].Source += add
						log.Println("skipping: ", cveId)
					}
					goto SKIP
				}
			}
			cveIdx = append(cveIdx, cveId)
			rr.CVEID = vuln.Identifiers.Cve[0]
			rr.PackageName = vuln.PackageName
			rr.Severity = vuln.SeverityWithCritical
			rr.Version = vuln.Version
			rr.FixedInVersion = vuln.NearestFixedInVersion
			rr.Description = vuln.Title
			rr.Source = vuln.From[0]
			rx = append(rx, rr)
		SKIP:
		}

	}
	csvfile, err := os.Create("consolidated_vulns.csv")
	if err != nil {
		log.Println("could not create csv file")
		return err
	}
	defer csvfile.Close()

	if err := gocsv.MarshalFile(rx, csvfile); err != nil {
		log.Println("error marshalling csv file")
		return err
	}

	return nil
}

func PullImage(ctx context.Context, cli *client.Client, imageName string) error {

	log.Println("Requested image: ", imageName)
	reader, err := cli.ImagePull(ctx, imageName, types.ImagePullOptions{})
	if err != nil {
		return err
	}
	io.Copy(os.Stdout, reader)
	defer reader.Close()

	return nil
}

func ScanImage(imageName string) error {

	cmd := exec.Command("docker", "scan", "--json", imageName)

	// Open a file to write the command output to
	fileName := fmt.Sprintf("%s_output.json", imageName)
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	// Set up a pipe to read the command's standard output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	// Start the command
	err = cmd.Start()
	if err != nil {
		return err
	}

	// Use io.Copy to copy the command's output to the file
	_, err = io.Copy(file, stdout)
	if err != nil {
		return err
	}

	// Wait for the command to finish
	cmd.Wait()

	// Read the output_json file
	jsonFile, err := os.Open(fileName)

	if err != nil {
		return err
	}
	defer jsonFile.Close()

	// Read the file into struct
	jsonbytes, err := io.ReadAll(jsonFile)
	if err != nil {
		return err
	}

	var dto SnykDTO

	json.Unmarshal(jsonbytes, &dto)

	return nil
}
