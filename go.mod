module github.com/bbmumford/shuttle

go 1.25.0

require (
	github.com/bbmumford/loom v0.0.6
	github.com/bbmumford/warrant v0.0.9
	github.com/bbmumford/weft v0.0.6
)

require github.com/google/uuid v1.6.0 // indirect

replace github.com/bbmumford/loom => ../loom

replace github.com/bbmumford/warrant => ../warrant

replace github.com/bbmumford/weft => ../weft
