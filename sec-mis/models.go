package secmis

type Rules struct {
	Ports        []string
	StringParams map[string]string
	FloatParams  map[string]float64
	BoolParams   map[string]bool
	IntParams    map[string]int32
}
