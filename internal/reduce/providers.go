package reduce

import "strings"

// provider is a third-party service a CNAME can point into. Claimable is true when an unclaimed name on
// the service can be registered by anyone, so a dangling CNAME to it is a takeover candidate (from the
// public can-i-take-over-xyz list). It is a hint, not a verified takeover. Edge is true for CDNs and
// load balancers that sit in front of the domain owner's own origin: the provider is written, but a
// CNAME to it is not a finding by itself.
type provider struct {
	suffix    string
	name      string
	claimable bool
	edge      bool
}

// providers are matched by suffix. The first entry that matches wins, so specific suffixes come before
// general ones (s3.amazonaws.com before amazonaws.com).
var providers = []provider{
	{"s3.amazonaws.com", "Amazon S3", true, false},
	{"s3-website", "Amazon S3", true, false},
	{"elasticbeanstalk.com", "AWS Elastic Beanstalk", true, false},
	{"cloudfront.net", "Amazon CloudFront", false, true},
	{"elb.amazonaws.com", "AWS ELB", false, true},
	{"awsglobalaccelerator.com", "AWS Global Accelerator", false, true},
	{"amazonaws.com", "AWS", false, false},
	{"github.io", "GitHub Pages", true, false},
	{"gitlab.io", "GitLab Pages", false, false},
	{"herokuapp.com", "Heroku", true, false},
	{"herokudns.com", "Heroku", true, false},
	{"herokuspace.com", "Heroku", false, false},
	{"azurewebsites.net", "Azure App Service", true, false},
	{"cloudapp.net", "Azure", true, false},
	{"cloudapp.azure.com", "Azure", true, false},
	{"trafficmanager.net", "Azure Traffic Manager", true, false},
	{"blob.core.windows.net", "Azure Blob Storage", true, false},
	{"azureedge.net", "Azure CDN", true, false},
	{"azure-api.net", "Azure API Management", true, false},
	{"azurefd.net", "Azure Front Door", false, true},
	{"windows.net", "Azure", false, false},
	{"fastly.net", "Fastly", false, true},
	{"netlify.app", "Netlify", false, false},
	{"netlify.com", "Netlify", false, false},
	{"vercel-dns.com", "Vercel", false, false},
	{"vercel.app", "Vercel", false, false},
	{"pages.dev", "Cloudflare Pages", false, false},
	{"cdn.cloudflare.net", "Cloudflare", false, true},
	{"pacloudflare.com", "Cloudflare", false, true},
	{"akamaiedge.net", "Akamai", false, true},
	{"edgekey.net", "Akamai", false, true},
	{"edgesuite.net", "Akamai", false, true},
	{"akamai.net", "Akamai", false, true},
	{"myshopify.com", "Shopify", true, false},
	{"zendesk.com", "Zendesk", false, false},
	{"freshdesk.com", "Freshdesk", false, false},
	{"helpscoutdocs.com", "Help Scout", true, false},
	{"ghost.io", "Ghost", true, false},
	{"pantheonsite.io", "Pantheon", true, false},
	{"readme.io", "ReadMe", true, false},
	{"surge.sh", "Surge", true, false},
	{"bitbucket.io", "Bitbucket", true, false},
	{"wordpress.com", "WordPress.com", true, false},
	{"wpengine.com", "WP Engine", false, false},
	{"unbouncepages.com", "Unbounce", false, false},
	{"webflow.io", "Webflow", false, false},
	{"hs-sites.com", "HubSpot", false, false},
	{"hubspot.net", "HubSpot", false, false},
	{"mktoweb.com", "Marketo", false, false},
	{"mktossl.com", "Marketo", false, false},
	{"sendgrid.net", "SendGrid", false, false},
	{"mailgun.org", "Mailgun", false, false},
	{"googlehosted.com", "Google", false, false},
	{"googleusercontent.com", "Google", false, false},
	{"appspot.com", "Google App Engine", false, false},
	{"firebaseapp.com", "Firebase", false, false},
	{"web.app", "Firebase", false, false},
	{"statuspage.io", "Statuspage", true, false},
	{"tumblr.com", "Tumblr", true, false},
	{"fly.dev", "Fly.io", false, false},
	{"onrender.com", "Render", false, false},
	{"ngrok.io", "ngrok", true, false},
	{"atlassian.net", "Atlassian", false, false},
	{"salesforce.com", "Salesforce", false, false},
	{"force.com", "Salesforce", false, false},
	{"cargocollective.com", "Cargo", true, false},
	{"agilecrm.com", "Agile CRM", true, false},
	{"uservoice.com", "UserVoice", true, false},
	{"smartjobboard.com", "SmartJobBoard", true, false},
	{"strikinglydns.com", "Strikingly", true, false},
	{"launchrock.com", "LaunchRock", true, false},
}

// Provider returns the service the CNAME chain points into, checking each name of the chain in order
// (the first is the one the domain owner configured). ok is false when no known service matches.
func Provider(chain []string) (p provider, ok bool) {
	for _, c := range chain {
		for _, p := range providers {
			if c == p.suffix || strings.HasSuffix(c, "."+p.suffix) || (p.suffix == "s3-website" && strings.Contains(c, ".s3-website")) {
				return p, true
			}
		}
	}
	return provider{}, false
}
