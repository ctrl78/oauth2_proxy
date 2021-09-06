package basic

import (
	"crypto/tls"
	"fmt"
	"strings"

	"log"

	"github.com/BurntSushi/toml"
	"github.com/go-ldap/ldap/v3"
)

type ldapServerConf struct {
	Host                       string           `toml:"host"`
	BaseBindDN                 string           `toml:"base_bind_dn"`
	Attr                       ldapAttributeMap `toml:"attributes"`
	Realm                      string           `toml:"realm"`
	SearchFilter               string           `toml:"search_filter"`
	ResolvedGroupsSearchFilter string           `toml:"resolved_groups_search_filter"`
	SearchBaseDnList           []string         `toml:"search_base_dns"`
	GroupDnList                []string         `toml:"group_dns"`
}
type ldapAttributeMap struct {
	MemberOf string `toml:"member_of"`
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
	ldapURL := "ldaps://" + a.Conf.Host + ":636"
	// To Remove when having a PKI
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

	// Search for the given username in ldap
	var searchResult *ldap.SearchResult
	for _, searchBase := range a.Conf.SearchBaseDnList {
		searchReq := ldap.SearchRequest{
			BaseDN:       searchBase,
			Scope:        ldap.ScopeWholeSubtree,
			DerefAliases: ldap.NeverDerefAliases,
			Attributes: []string{
				a.Conf.Attr.MemberOf,
			},
			Filter: strings.Replace(a.Conf.SearchFilter, "%s", ldap.EscapeFilter(user), -1),
		}

		searchResult, err = l.Search(&searchReq)
		if err != nil {
			log.Printf("LDAP: Unable to search for user '%s': %s", user, err)
		}

		if len(searchResult.Entries) > 0 {
			break
		}
	}

	if len(searchResult.Entries) != 1 {
		log.Printf("LDAP: User does not exist or too many entries returned")
		return false
	}

	userdn := searchResult.Entries[0].DN

	// Case no allowed group is configured
	if a.Conf.GroupDnList == nil {
		return true
	}

	// Case any allowed group is part of member_of attribute
	for _, allowedGroupDN := range a.Conf.GroupDnList {
		for _, groupDN := range searchResult.Entries[0].GetAttributeValues("memberOf") {
			if groupDN == allowedGroupDN {
				return true
			}
		}
	}

	// Case any allowed group is not part of member_of attribute
	// Search for the resolved groups.
	var resolvedGroupsSearchResult *ldap.SearchResult
	for _, searchBase := range a.Conf.SearchBaseDnList {
		resolvedGroupSearchReq := ldap.SearchRequest{
			BaseDN:       searchBase,
			Scope:        ldap.ScopeWholeSubtree,
			DerefAliases: ldap.NeverDerefAliases,
			Filter:       strings.Replace(a.Conf.ResolvedGroupsSearchFilter, "%s", ldap.EscapeFilter(userdn), -1),
		}

		resolvedGroupsSearchResult, err = l.Search(&resolvedGroupSearchReq)
		if err != nil {
			log.Printf("LDAP: Unable to search for resolved groups for user '%s': %s", user, err)
		}

		if len(resolvedGroupsSearchResult.Entries) > 0 {
			break
		}
	}

	for _, allowedGroupDN := range a.Conf.GroupDnList {
		for _, group := range resolvedGroupsSearchResult.Entries {
			if group.DN == allowedGroupDN {
				return true
			}
		}
	}

	// Case none of allowed group is part of resolved groups.
	log.Printf("Invalid LDAP group membership for %s.", user)
	return false
}
