package register

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/varwof/pkcs7"
)

// SignCapability signs a capability JSON file using PKCS#7 detached signature.
// certPath: PEM certificate chain (signer cert + intermediates)
// keyPath: PEM private key
// capPath: path to capability.json
// outputPath: path to write .p7s file (defaults to capPath + ".p7s")
func SignCapability(certPath, keyPath, capPath, outputPath string) error {
	capData, err := os.ReadFile(capPath)
	if err != nil {
		return fmt.Errorf("read capability: %w", err)
	}

	// load certificate chain
	certs, err := LoadCertFile(certPath)
	if err != nil {
		return fmt.Errorf("load certs: %w", err)
	}
	signerCert := certs[0]
	var chain []*x509.Certificate
	if len(certs) > 1 {
		chain = certs[1:]
	}

	// load private key
	privKey, err := loadPrivateKey(keyPath)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}

	// build PKCS#7 signed data (detached)
	p7sDER, err := pkcs7.BuildSignedData(
		pkcs7.OIDData,
		capData,
		signerCert,
		privKey,
		chain,
	)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	// write .p7s file
	if outputPath == "" {
		outputPath = capPath + ".p7s"
	}
	p7sPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PKCS7",
		Bytes: p7sDER,
	})
	if err := os.WriteFile(outputPath, p7sPEM, 0644); err != nil {
		return fmt.Errorf("write %s: %w", outputPath, err)
	}

	fmt.Printf("Signed %s → %s\n", capPath, outputPath)
	fmt.Printf("  Signer: %s (SN: %s)\n", signerCert.Subject.CommonName, signerCert.SerialNumber)
	if len(chain) > 0 {
		fmt.Printf("  Chain: %d intermediate(s)\n", len(chain))
	}
	return nil
}

// VerifyCapabilityPKCS7 verifies a capability JSON against its .p7s signature.
// trustRoots: PEM root/intermediate certificates for chain verification.
func VerifyCapabilityPKCS7(capPath string, trustRoots []*x509.Certificate) error {
	sigPath := capPath + ".p7s"
	capData, err := os.ReadFile(capPath)
	if err != nil {
		return fmt.Errorf("read capability: %w", err)
	}
	sigPEM, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}

	// decode PEM
	block, _ := pem.Decode(sigPEM)
	if block == nil {
		return fmt.Errorf("invalid PEM in %s", sigPath)
	}

	// verify detached signature
	signerCert, err := pkcs7.VerifyDetached(block.Bytes, capData)
	if err != nil {
		return fmt.Errorf("PKCS#7 verify: %w", err)
	}

	// verify certificate chain
	if len(trustRoots) > 0 {
		roots := x509.NewCertPool()
		for _, root := range trustRoots {
			roots.AddCert(root)
		}
		opts := x509.VerifyOptions{
			Roots:     roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		}
		if _, err := signerCert.Verify(opts); err != nil {
			return fmt.Errorf("certificate chain verify: %w", err)
		}
	}

	return nil
}

// HasSignature checks if a .p7s file exists for the given capability file.
func HasSignature(capPath string) bool {
	_, err := os.Stat(capPath + ".p7s")
	return err == nil
}

// LoadCertFile reads all certificates in a certificate chain from a PEM file.
func LoadCertFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates in %s", path)
	}
	return certs, nil
}

func loadPrivateKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM")
	}
	// try PKCS8
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("key does not implement crypto.Signer")
		}
		return signer, nil
	}
	// try EC
	key2, err := x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return key2, nil
	}
	// try RSA
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// LoadTrustRoots loads PEM certificates from a file or directory.
func LoadTrustRoots(path string) ([]*x509.Certificate, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return LoadCertFile(path)
	}
	var certs []*x509.Certificate
	err = filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".pem") && !strings.HasSuffix(p, ".crt") {
			return nil
		}
		c, err := LoadCertFile(p)
		if err != nil {
			return nil
		}
		certs = append(certs, c...)
		return nil
	})
	return certs, err
}

// GetSignerCert extracts the signer certificate from a .p7s file.
func GetSignerCert(p7sPath string) (*x509.Certificate, error) {
	pepP7s, err := os.ReadFile(p7sPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pepP7s)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM")
	}

	var ci pkcs7.ContentInfo
	if _, err := asn1.Unmarshal(block.Bytes, &ci); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	var sd pkcs7.SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("unmarshal signed data: %w", err)
	}
	if len(sd.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates in signature")
	}
	return x509.ParseCertificate(sd.Certificates[0].FullBytes)
}
