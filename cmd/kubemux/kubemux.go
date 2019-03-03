package kubemux

import (
	"context"
	goflag "flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	colorable "github.com/mattn/go-colorable"
	homedir "github.com/mitchellh/go-homedir"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	validator "gopkg.in/go-playground/validator.v9"
	cliflag "k8s.io/component-base/cli/flag"
	kubectl "k8s.io/kubernetes/pkg/kubectl/cmd"
)

var (
	vault     string
	clusters  []string
	validate  = validator.New()
	appID     string
	appKey    string
	appTenant string
	authArgs  = map[string]string{
		"AppID":     appID,
		"AppKey":    appKey,
		"AppTenant": appTenant,
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := newKubemuxCommand().Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	log.SetLevel(log.InfoLevel)
	log.SetOutput(colorable.NewColorableStdout())
	rand.Seed(time.Now().UnixNano())

	pflag.CommandLine.SetNormalizeFunc(cliflag.WordSepNormalizeFunc)
	pflag.CommandLine.AddGoFlagSet(goflag.CommandLine)
}

func newKubemuxCommand() *cobra.Command {
	kubeconfigPath, err := homedir.Expand("~/.kube/config")
	FailOnError("Failed determining home dir.", err)

	var command = &cobra.Command{
		Use:   "kubemux",
		Args:  cobra.MinimumNArgs(1),
		Short: "kubemux",
		Long: `kubemux runs a single kubectl command across multiple clusters, fetching
their kubeconfigs from the specified vault as desired.`,
		Run: func(cmd *cobra.Command, args []string) {
			Mux(args, kubeconfigPath)
		},
	}

	cleanCmd := &cobra.Command{
		Use:   "clean",
		Short: "Clean kubeconfig file from system.",
		Long: `kubemux has an edge case which may allow kubeconfig files with
sensitive credentials to stay on the system after a bad run. "kubemux clean" should
be run after every invocation of kubemux to ensure a clean system.`,
		Run: func(cmd *cobra.Command, args []string) {
			RemoveKubeconfig(kubeconfigPath)
		},
	}

	command.PersistentFlags().StringVar(&vault, "vault", "", "Azure Key Vault URL.")
	command.PersistentFlags().StringSliceVar(&clusters, "clusters", []string{}, "Comma seperated list of clusters. Also can specify by using flag multiple times.")
	command.PersistentFlags().StringVar(&appID, "AppId", "", "Application ID of deployment service principal.")
	command.PersistentFlags().StringVar(&appKey, "AppKey", "", "Secret key of deployment service principal.")
	command.PersistentFlags().StringVar(&appTenant, "AppTenant", "", "Tenant of deployment service principal.")
	command.AddCommand(cleanCmd)
	return command
}

// Mux runs a kubectl command across many clusters, downloading their kubeconfig files one by one from Key Vault
func Mux(args []string, path string) {
	client := NewKeyVaultClient()
	kubectlCmd := kubectl.NewDefaultKubectlCommand()
	for _, cluster := range clusters {
		kubeconfig := DownloadKubeconfig(client, vault, cluster, path)
		kubectlCmd.Flags().Set("kubeconfig", kubeconfig)
		kubectlCmd.SetArgs(args)
		err := kubectlCmd.Execute()
		// NOTE: will not run unless kubectl exits successfully.
		// Kubectl selects certain errors as hard failures and calls os.Exit(1) fairly deep internally.
		// Other errors allow completion of execution, and this will also run for successful commands
		RemoveKubeconfig(path)
		FailOnError("Kubectl failed.", err)
	}
}

// DownloadKubeconfig creates a temp file to hold the kubeconfig.
func DownloadKubeconfig(client keyvault.BaseClient, vault string, cluster string, path string) string {
	kubeconfig, err := client.GetSecret(context.Background(), fmt.Sprintf("https://%s.vault.azure.net/", vault), fmt.Sprintf("kubeconfig--%s", cluster), "")
	FailOnError("Failed to acquire secret from KV.", err)

	// kubeconfigFile, err := os.Open(kubeconfigPath)
	// FailOnError("Failed to create temporary file.", err)
	// defer kubeconfigFile.Close()
	// log.WithField("tmpfile", kubeconfigFile.Name).Info("Opened tmp file to hold kubeconfig.")

	err = ioutil.WriteFile(path, []byte(*kubeconfig.Value), 0644)
	FailOnError("Failed to write kubeconfig", err)
	log.Info("Wrote kubeconfig.")

	return path
}

// RemoveKubeconfig removes the kubeconfig tmp file from disk
func RemoveKubeconfig(path string) {
	log.Info("Removing kubeconfig.")
	FailOnError("Failed to remove kubeconfig from disk.", os.Remove(path))
	log.Info("Succeeded removing kubeconfig.")
}

// IsCLI checks whether to try CLI or Service Principal auth. If SP, it validates the arguments.
func IsCLI() bool {
	empty := make([]string, 0)
	for arg, val := range authArgs {
		if val == "" {
			empty = append(empty, arg)
		}
	}
	if len(empty) == 0 {
		return false
	}
	if len(empty) < 3 {
		log.WithField("Missing", strings.Join(empty, ", ")).Fatalf("Auth fields partially populated. Indicative of misconfiguration")
	}
	return true
}

// Any returns true if one of the strings in the slice satisfies the predicate f.
func Any(vs []string, f func(string) bool) bool {
	for _, v := range vs {
		if f(v) {
			return true
		}
	}
	return false
}

// NewKeyVaultClient returns an authenticated Key Vault client
func NewKeyVaultClient() keyvault.BaseClient {
	if IsCLI() {
		return NewKeyVaultClientFromCLI()
	}
	return NewKeyVaultClientFromAppKey(appID, appKey, appTenant)
}

// NewKeyVaultClientFromCLI returns a Key Vault client authenticated in the background using Azure CLI.
func NewKeyVaultClientFromCLI() keyvault.BaseClient {
	// Determine KV resource based on environment
	resource, err := GetKeyVaultResource()
	FailOnError("Failed to get CLI KeyVault token resource.", err)

	// Authorize to KV
	authorizer, err := auth.NewAuthorizerFromCLIWithResource(resource)
	FailOnError("Failed to create KV authorizer from CLI.", err)
	client := keyvault.New()
	client.Authorizer = authorizer
	return client
}

// NewKeyVaultClientFromAppKey returns a Key Vault client authenticated using a Service Principal client app ID, secret, and tenant ID.
func NewKeyVaultClientFromAppKey(appID string, appKey string, appTenant string) keyvault.BaseClient {
	// Determine KV resource based on environment
	resource, err := GetKeyVaultResource()
	FailOnError("Failed to get KeyVault token resource.", err)

	// Authorize to KV
	authorizer := ClientCredentialsAuthorizerWithResource(resource, appID, appKey, appTenant)
	client := keyvault.New()
	client.Authorizer = authorizer
	return client
}

// ClientCredentialsAuthorizerWithResource creates an authorizer from the available client credentials and the specified resource.
func ClientCredentialsAuthorizerWithResource(resource string, appID string, appKey string, appTenant string) autorest.Authorizer {
	config, err := adal.NewOAuthConfig(azure.PublicCloud.ActiveDirectoryEndpoint, appTenant)
	FailOnError("Failed to create adal OAuth config.", err)

	spToken, err := adal.NewServicePrincipalToken(*config, appID, appKey, resource)
	FailOnError("Failed to create adal OAuth token.", err)

	return autorest.NewBearerAuthorizer(spToken)
}

// GetKeyVaultResource returns the token audience for KeyVault in an Azure environment
func GetKeyVaultResource() (string, error) {
	envName := os.Getenv("AZURE_ENVIRONMENT")
	var env azure.Environment
	var err error

	if envName == "" {
		env = azure.PublicCloud
	} else {
		env, err = azure.EnvironmentFromName(envName)
		if err != nil {
			return "", err
		}
	}

	resource := os.Getenv("AZURE_KEYVAULT_RESOURCE")
	if resource == "" {
		resource = strings.TrimSuffix(env.KeyVaultEndpoint, "/")
	}

	return resource, nil
}

// FailOnError assists with logging failures and exiting.
func FailOnError(msg string, err error) {
	if err != nil {
		log.WithFields(log.Fields{
			"error": err.Error(),
		}).Fatal(msg)
	}
}
