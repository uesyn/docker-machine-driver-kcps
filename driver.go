package dockermachinedriverkcps

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/uesyn/gokcps"
	"golang.org/x/crypto/ssh"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/state"
)

const (
	DockerPort              = 2376
	DefaultNetwork          = "PublicFrontSegment"
	DefaultSSHUser          = "ubuntu"
	DefaultSSHPort          = 22
	DefaultEngineInstallURL = "https://get.docker.com"
	DefaultIngressCIDR      = "0.0.0.0/0"
	DefaultServiceOffering  = "Medium2(2vCPU,Mem8GB)"
)

// Driver is docker machine driver struct
type Driver struct {
	*drivers.BaseDriver
	ID                string
	ApiURL            string
	ApiKey            string
	SecretKey         string
	IPAddressID       string
	PrivateIPAddress  string
	UsePrivateIP      string
	PrivateIPOnly     string
	Password          string
	IngressCIDR       string
	Template          string
	TemplateID        string
	ServiceOffering   string
	ServiceOfferingID string
	Network           string
	NetworkID         string
	Zone              string
	ZoneID            string
	Swarmport         int
	client            *gokcps.KCPSClient
}

type configError struct {
	option string
}

func (e *configError) Error() string {
	return fmt.Sprintf("kcps driver requires the --kcps-%s option", e.option)
}

func NewDriver(hostName, storePath string) drivers.Driver {

	driver := &Driver{
		BaseDriver: &drivers.BaseDriver{
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
	return driver
}

// GetCreateFlags registers the flags this driver adds to
// "docker hosts create"
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:   "kcps-api-url",
			Usage:  "kcps API URL",
			EnvVar: "KCPS_API_URL",
		},
		mcnflag.StringFlag{
			Name:   "kcps-api-key",
			Usage:  "kcps API key",
			EnvVar: "KCPS_API_KEY",
		},
		mcnflag.StringFlag{
			Name:   "kcps-secret-key",
			Usage:  "kcps API secret key",
			EnvVar: "KCPS_SECRET_KEY",
		},
		mcnflag.StringFlag{
			Name:  "kcps-ssh-user",
			Usage: fmt.Sprint("SSH user. Default: %s", DefaultSSHUser),
			Value: DefaultSSHUser,
		},
		mcnflag.IntFlag{
			Name:  "kcps-ssh-port",
			Usage: fmt.Sprintf("SSH port. Default: %d", DefaultSSHPort),
			Value: DefaultSSHPort,
		},
		mcnflag.StringFlag{
			Name:  "kcps-network",
			Usage: fmt.Sprintf("Network Name. Default: %s ", DefaultNetwork),
			Value: DefaultNetwork,
		},
		mcnflag.StringFlag{
			Name:  "kcps-ingress-cidr",
			Usage: fmt.Sprintf("Source CIDR to give access to the machine. Format is 'xxx.xxx.xxx.xxx/xx'. Default: 'docker-machine-client-ip' "),
		},
		mcnflag.StringFlag{
			Name:  "kcps-template",
			Usage: "kcps virtual machine template name",
		},
		mcnflag.StringFlag{
			Name:  "kcps-service-offering",
			Usage: fmt.Sprintf("kcps service offering name. Default: %s ", DefaultServiceOffering),
			Value: DefaultServiceOffering,
		},
		mcnflag.StringFlag{
			Name:   "kcps-zone",
			Usage:  "kcps zone name",
			EnvVar: "KCPS_ZONE",
		},
	}
}

func (d *Driver) SetZone(zonename string) error {

	cs := d.getKCPSClient()
	d.Zone = zonename

	zoneid, err := getZoneID(cs, d.Zone)
	if err != nil {
		return err
	}
	log.Info("zoneid: ", zoneid)

	d.ZoneID = zoneid
	return nil
}

func (d *Driver) SetTemplate(tempname string) error {

	cs := d.getKCPSClient()
	d.Template = tempname

	tempid, err := getTemplateID(cs, d.Template)
	if err != nil {
		return err
	}
	log.Info("tempid: ", tempid)
	d.TemplateID = tempid
	return nil
}

func (d *Driver) SetServiceOffering(ofname string) error {
	cs := d.getKCPSClient()
	d.ServiceOffering = ofname

	offid, err := getServiceOfferingID(cs, d.ServiceOffering)
	if err != nil {
		return err
	}
	log.Info("offeringid: ", offid)
	d.ServiceOfferingID = offid
	return nil
}

func (d *Driver) SetNetwork(network string) error {

	cs := d.getKCPSClient()
	d.Network = network

	netid, err := getNetworkID(cs, d.Network)
	if err != nil {
		return err
	}
	log.Info("netid: ", netid)
	d.NetworkID = netid
	return nil
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.ApiURL = flags.String("kcps-api-url")
	d.ApiKey = flags.String("kcps-api-key")
	d.SecretKey = flags.String("kcps-secret-key")
	d.SSHUser = flags.String("kcps-ssh-user")
	d.SSHPort = flags.Int("kcps-ssh-port")
	d.IngressCIDR = flags.String("kcps-ingress-cidr")
	d.Network = flags.String("kcps-network")
	d.Zone = flags.String("kcps-zone")
	d.Template = flags.String("kcps-template")
	d.ServiceOffering = flags.String("kcps-service-offering")

	if d.Network == "" {
		return &configError{option: "network"}
	}
	if d.ApiURL == "" {
		return &configError{option: "api-url"}
	}

	if d.ApiKey == "" {
		return &configError{option: "api-key"}
	}

	if d.SecretKey == "" {
		return &configError{option: "secret-key"}
	}

	if d.Template == "" {
		return &configError{option: "template"}
	}

	if d.ServiceOffering == "" {
		return &configError{option: "service-offering"}
	}

	if d.Zone == "" {
		return &configError{option: "zone"}
	}

	if d.IngressCIDR == "" {
		resp, err := http.Get("http://inet-ip.info/ip")
		if err != nil {
			fmt.Println(err)
		}
		defer resp.Body.Close()
		scn := bufio.NewScanner(resp.Body)
		if scn.Scan() == true {
			d.IngressCIDR = scn.Text() + "/32"
		} else {
			return &configError{option: "kcps-ingress-cidr"}
		}

	}

	if err := d.SetZone(flags.String("kcps-zone")); err != nil {
		return err
	}
	if err := d.SetTemplate(flags.String("kcps-template")); err != nil {
		return err
	}
	if err := d.SetServiceOffering(flags.String("kcps-service-offering")); err != nil {
		return err
	}
	if err := d.SetNetwork(flags.String("kcps-network")); err != nil {
		return err
	}

	return nil
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return "kcps"
}

// PreCreateCheck is called to enforce pre-creation steps
func (d *Driver) PreCreateCheck() error {
	return nil
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

func (d *Driver) GetURL() (string, error) {
	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("tcp://%s:%d", ip, DockerPort), nil
}

func (d *Driver) getKCPSClient() *gokcps.KCPSClient {
	if d.client != nil {
		return d.client
	}
	cs := gokcps.NewAsyncClient(d.ApiURL, d.ApiKey, d.SecretKey, false)
	d.client = cs
	return cs
}

func (d *Driver) Create() error {
	ins := NewKCPSInstance(d)
	log.Info("Instance creating")
	err := ins.Create()
	if err != nil {
		return err
	}
	log.Info("Instance created. ID:", d.ID, "Password:", d.Password)
	log.Info("Wait for Instance which state is Running")
	err = ins.WaitStatus(VM_STATE_RUNNING, 30*time.Minute)
	if err != nil {
		return err
	}
	log.Info("Instance state is running")

	log.Info("Start AssingIP")
	err = ins.AssingIP()
	if err != nil {
		return err
	}
	log.Info("Assinged IP ID:", d.IPAddressID, "IPAddress:", d.IPAddress)

	log.Info("Start SetFirewall.")
	err = ins.SetFirewall()
	if err != nil {
		return err
	}
	log.Info("Firewall is setted.")

	log.Info("Wait for opening SSH port.")
	err = waitForSSHPortOpen(d.IPAddress, d.SSHPort)
	if err != nil {
		return err
	}
	log.Info("SSH port is oppend.")

	// Create SSH Key pair
	log.Info("Create SSH Key")
	if err := GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
		return err
	}

	// Inject SSH Key
	log.Info("SSH Key Injection")
	if err := injectSSHPubKey(d.IPAddress, d.SSHUser, strconv.Itoa(d.SSHPort), d.Password, d.GetSSHKeyPath()+".pub"); err != nil {
		return err
	}
	return nil
}

func (d *Driver) GetState() (state.State, error) {
	ins := NewKCPSInstance(d)
	s, err := ins.GetState()
	if err != nil {
		return state.None, err
	}

	switch s {
	case VM_STATE_STARTING:
		return state.Starting, nil
	case VM_STATE_RUNNING:
		return state.Running, nil
	case VM_STATE_STOPPING:
		return state.Running, nil
	case VM_STATE_STOPPED:
		return state.Stopped, nil
	case VM_STATE_DESTROYED:
		return state.Stopped, nil
	case VM_STATE_EXPUNGING:
		return state.Stopped, nil
	case VM_STATE_MIGRATING:
		return state.Paused, nil
	case VM_STATE_ERROR:
		return state.Error, nil
	case VM_STATE_UNKNOWN:
		return state.Error, nil
	case VM_STATE_SHUTDOWNED:
		return state.Stopped, nil
	}

	return state.None, nil
}

func (d *Driver) Kill() error {
	ins := NewKCPSInstance(d)
	return ins.Kill()
}

func (d *Driver) Restart() error {
	ins := NewKCPSInstance(d)
	return ins.Restart()
}

func (d *Driver) Start() error {
	ins := NewKCPSInstance(d)
	return ins.Start()
}

func (d *Driver) Remove() error {
	ins := NewKCPSInstance(d)
	if err := ins.WithdrawIP(); err != nil {
		return err
	}

	if err := ins.Remove(); err != nil {
		return err
	}
	return nil
}

func (d *Driver) Stop() error {
	ins := NewKCPSInstance(d)
	if err := ins.Stop(); err != nil {
		return err
	}
	return nil
}

var (
	ErrKeyGeneration     = errors.New("Unable to generate key")
	ErrValidation        = errors.New("Unable to validate key")
	ErrPublicKey         = errors.New("Unable to convert public key")
	ErrUnableToWriteFile = errors.New("Unable to write file")
)

type KeyPair struct {
	PrivateKey []byte
	PublicKey  []byte
}

// NewKeyPair generates a new SSH keypair
// This will return a private & public key encoded as DER.
func NewKeyPair() (keyPair *KeyPair, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, ErrKeyGeneration
	}

	if err := priv.Validate(); err != nil {
		return nil, ErrValidation
	}

	privDer := x509.MarshalPKCS1PrivateKey(priv)

	pubSSH, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, ErrPublicKey
	}

	return &KeyPair{
		PrivateKey: privDer,
		PublicKey:  ssh.MarshalAuthorizedKey(pubSSH),
	}, nil
}

// WriteToFile writes keypair to files
func (kp *KeyPair) WriteToFile(privateKeyPath string, publicKeyPath string) error {
	files := []struct {
		File  string
		Type  string
		Value []byte
	}{
		{
			File:  privateKeyPath,
			Value: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: nil, Bytes: kp.PrivateKey}),
		},
		{
			File:  publicKeyPath,
			Value: kp.PublicKey,
		},
	}

	for _, v := range files {
		f, err := os.Create(v.File)
		if err != nil {
			return ErrUnableToWriteFile
		}

		if _, err := f.Write(v.Value); err != nil {
			return ErrUnableToWriteFile
		}

		// windows does not support chmod
		switch runtime.GOOS {
		case "darwin", "linux", "freebsd":
			if err := f.Chmod(0600); err != nil {
				return err
			}
		}
	}

	return nil
}

func GenerateSSHKey(path string) error {
	if _, err := os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("Desired directory for SSH keys does not exist: %s", err)
		}

		kp, err := NewKeyPair()
		if err != nil {
			return fmt.Errorf("Error generating key pair: %s", err)
		}

		if err := kp.WriteToFile(path, fmt.Sprintf("%s.pub", path)); err != nil {
			return fmt.Errorf("Error writing keys to file(s): %s", err)
		}
	}

	return nil
}
