package dockermachinedriverkcps

import (
	"fmt"
	//	"github.com/docker/machine/libmachine/log"
	"time"
)

const (
	VM_STATE_STARTING   = "Starting"
	VM_STATE_RUNNING    = "Running"
	VM_STATE_STOPPING   = "Stopping"
	VM_STATE_STOPPED    = "Stopped"
	VM_STATE_DESTROYED  = "Destroyed"
	VM_STATE_EXPUNGING  = "Expunging"
	VM_STATE_MIGRATING  = "Migrating"
	VM_STATE_ERROR      = "Error"
	VM_STATE_UNKNOWN    = "Unknown"
	VM_STATE_SHUTDOWNED = "Shutdowned"
)

type KCPSInstance struct {
	d *Driver
}

func NewKCPSInstance(d *Driver) *KCPSInstance {
	k := &KCPSInstance{d}
	return k
}

// Create KCPS Instance
func (k *KCPSInstance) Create() error {
	client := k.d.getKCPSClient()
	driver := k.d
	dparam := client.VirtualMachine.NewDeployValueVirtualMachineParams(
		k.d.ServiceOfferingID,
		k.d.TemplateID,
		k.d.ZoneID,
		k.d.GetMachineName(),
	)

	r1, err := client.VirtualMachine.DeployValueVirtualMachine(dparam)
	if err != nil {
		return err
	}
	driver.ID = r1.Id
	driver.Password = r1.Password
	driver.PrivateIPAddress = r1.Nic[0].Ipaddress
	return nil
}

// Assign IP to KCPS Instance
func (k *KCPSInstance) AssingIP() error {
	// Get Global IP
	client := k.d.getKCPSClient()
	driver := k.d
	p := client.Nic.NewAssociateIpAddressParams(driver.NetworkID)

	r1, err := client.Nic.AssociateIpAddress(p)
	if err != nil {
		return err
	}
	driver.IPAddress = r1.Ipaddress
	driver.IPAddressID = r1.Id

	// Assign Global IP to KCPS Instance
	p2 := client.Firewall.NewEnableStaticNatParams(driver.IPAddressID, driver.ID)
	_, err = client.Firewall.EnableStaticNat(p2)
	if err != nil {
		return err
	}

	return nil
}

func (k *KCPSInstance) WithdrawIP() error {
	client := k.d.getKCPSClient()
	driver := k.d
	// Withdraw Global IP from KCPS Instance
	p2 := client.Firewall.NewDisableStaticNatParams(driver.IPAddressID)
	_, err := client.Firewall.DisableStaticNat(p2)
	if err != nil {
		return err
	}

	// Dissassociate Global IP
	p := client.Nic.NewDisassociateIpAddressParams(driver.IPAddressID)
	_, err = client.Nic.DisassociateIpAddress(p)
	if err != nil {
		return err
	}
	return nil
}

func (k *KCPSInstance) SetFirewall() error {
	client := k.d.client
	driver := k.d

	// For IPSec
	p1 := client.Firewall.NewCreateFirewallRuleParams(driver.IPAddressID, "udp", []string{"0.0.0.0/0"})
	p1.SetStartport(500)
	p1.SetEndport(500)
	_, err := client.Firewall.CreateFirewallRule(p1)
	if err != nil {
		return err
	}

	// For IPSec
	p2 := client.Firewall.NewCreateFirewallRuleParams(driver.IPAddressID, "udp", []string{"0.0.0.0/0"})
	p2.SetStartport(4500)
	p2.SetEndport(4500)
	_, err = client.Firewall.CreateFirewallRule(p2)
	if err != nil {
		return err
	}

	// For vxlan
	p3 := client.Firewall.NewCreateFirewallRuleParams(driver.IPAddressID, "udp", []string{"0.0.0.0/0"})
	p3.SetStartport(4789)
	p3.SetEndport(4789)
	_, err = client.Firewall.CreateFirewallRule(p3)
	if err != nil {
		return err
	}

	// For SSH
	p4 := client.Firewall.NewCreateFirewallRuleParams(
		driver.IPAddressID,
		"tcp",
		[]string{driver.IngressCIDR},
	)
	p4.SetStartport(driver.SSHPort)
	p4.SetEndport(driver.SSHPort)

	_, err = client.Firewall.CreateFirewallRule(p4)
	if err != nil {
		return err
	}

	// For docker-machine
	p5 := client.Firewall.NewCreateFirewallRuleParams(
		driver.IPAddressID,
		"tcp",
		[]string{driver.IngressCIDR},
	)
	p5.SetStartport(DockerPort)
	p5.SetEndport(DockerPort)
	_, err = client.Firewall.CreateFirewallRule(p5)
	if err != nil {
		return err
	}
	return nil
}

func (k *KCPSInstance) Kill() error {
	driver := k.d
	client := driver.getKCPSClient()
	p := client.VirtualMachine.NewStopVirtualMachineParams(driver.ID)
	p.SetForced(true)
	_, err := client.VirtualMachine.StopVirtualMachine(p)
	if err != nil {
		return err
	}
	return nil
}

func (k *KCPSInstance) Remove() error {
	driver := k.d
	client := driver.getKCPSClient()
	p := client.VirtualMachine.NewDestroyVirtualMachineParams(driver.ID)
	_, err := client.VirtualMachine.DestroyVirtualMachine(p)
	if err != nil {
		return err
	}
	return nil
}

func (k *KCPSInstance) Start() error {
	driver := k.d
	client := driver.getKCPSClient()
	p := client.VirtualMachine.NewStartVirtualMachineParams(driver.ID)
	_, err := client.VirtualMachine.StartVirtualMachine(p)
	if err != nil {
		return err
	}
	return nil
}

func (k *KCPSInstance) Stop() error {
	driver := k.d
	client := driver.getKCPSClient()
	p := client.VirtualMachine.NewStopVirtualMachineParams(driver.ID)
	_, err := client.VirtualMachine.StopVirtualMachine(p)
	if err != nil {
		return err
	}
	return nil
}

func (k *KCPSInstance) Restart() error {
	driver := k.d
	client := driver.getKCPSClient()
	p := client.VirtualMachine.NewRebootVirtualMachineParams(driver.ID)
	_, err := client.VirtualMachine.RebootVirtualMachine(p)
	if err != nil {
		return err
	}
	return nil
}

func (k *KCPSInstance) GetState() (string, error) {
	driver := k.d
	client := driver.getKCPSClient()
	p := client.VirtualMachine.NewListVirtualMachinesParams()
	p.SetId(driver.ID)
	r, err := client.VirtualMachine.ListVirtualMachines(p)
	if err != nil {
		return "", err
	}
	return r.VirtualMachines[0].State, nil
}

func (k *KCPSInstance) WaitStatus(status string, timeout time.Duration) error {
	t := time.After(timeout)
	for {
		select {
		case <-t:
			return fmt.Errorf("Timeout VM WaitStatus")
		default:
			s, err := k.GetState()
			if err != nil {
				return fmt.Errorf("WaitStatus Error: %v", err)
			}
			if s == status {
				return nil
			}
			time.Sleep(10 * time.Second)
		}
	}
}
