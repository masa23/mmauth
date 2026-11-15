module github.com/masa23/mmauth

go 1.19

require (
	github.com/cloudflare/circl v1.6.3
	golang.org/x/net v0.35.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
)

replace github.com/cloudflare/circl => ./dkim2/internal/circl
