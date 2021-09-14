package basic

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/BurntSushi/toml"
	"github.com/go-ldap/ldap/v3"
)

type ldapServerConf struct {
	Host         string   `toml:"host"`
	Port         int      `toml:"port"`
	Realm        string   `toml:"realm"`
	SearchBaseDn string   `toml:"search_base"`
	Groups       []string `toml:"groups"`
}

// LdapAuthenticator represents the structure of an ldap authenticator
type LdapAuthenticator struct {
	Conf *ldapServerConf
}

// NewLdapAuthenticatorFromFile consctructs an LdapAuthenticator from the file at the path given
func NewLdapAuthenticatorFromFile(path string) (*LdapAuthenticator, error) {
	var conf ldapServerConf
	if _, err := toml.DecodeFile(path, &conf); err != nil {
		return nil, err
	}

	return newLdapAuthenticator(&conf)
}

func newLdapAuthenticator(conf *ldapServerConf) (*LdapAuthenticator, error) {
	return &LdapAuthenticator{Conf: conf}, nil
}

// Validate checks a users password against the LdapAuthenticator
func (a *LdapAuthenticator) Validate(user string, password string) bool {
	ldapURL := fmt.Sprintf("ldaps://%s:%d", a.Conf.Host, a.Conf.Port)
	// To Remove when having a PKI(we allow self sign certificates)
	/* #nosec */
	l, err := ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))

	if err != nil {
		log.Printf("LDAP: Unable to dial %s: %s", ldapURL, err)
		return false
	}
	defer l.Close()
	fullUser := user + "@" + a.Conf.Realm
	bindRequest := ldap.NewSimpleBindRequest(fullUser, password, nil)
	// First validate user password
	_, err = l.SimpleBind(bindRequest)

	if err != nil {
		log.Printf("LDAP: Unable to bind as user '%s':'%s'", user, err)
		return false
	}
	// check if groups Acls are in place
	if len(a.Conf.Groups) == 0 {
		log.Printf("LDAP: Cannot continue there is no groups configured to control access")
		return false
	}
	for _, group := range a.Conf.Groups {
		// Get the DN of the group
		filter := fmt.Sprintf("(CN=%s)", ldap.EscapeFilter(group))
		searchReq := ldap.NewSearchRequest(a.Conf.SearchBaseDn, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, []string{"sAMAccountName"}, nil)

		resultDn, err := l.Search(searchReq)
		if err != nil {
			log.Printf("LDAP: Unable to find group '%s'", group)
			return false
		}

		// Get the members of a given group using DN
		groupDN := resultDn.Entries[0].DN
		filterMembers := fmt.Sprintf("(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=%s))", ldap.EscapeFilter(groupDN))
		searchReqMembers := ldap.NewSearchRequest(a.Conf.SearchBaseDn, ldap.ScopeWholeSubtree, 0, 0, 0, false, filterMembers, []string{"sAMAccountName"}, nil)
		resultMembers, err := l.Search(searchReqMembers)

		if err != nil {
			log.Printf("LDAP: Unable to get members of group '%s'", group)
			return false
		}

		for _, accountName := range resultMembers.Entries {
			if accountName.GetAttributeValue("sAMAccountName") == user {
				log.Printf("Account is member of %s", groupDN)
				return true
			}

		}
	}
	log.Printf("Invalid LDAP group membership for %s.", user)
	return false

}
