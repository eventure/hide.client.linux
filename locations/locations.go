package locations

type Geo struct {
	Latitude		float64		`json:"lat"`
	Longitude		float64		`json:"lon"`
	CityName		string		`json:"cityName"`
	CountryCode		string		`json:"countryCode"`
	Continent		string		`json:"continent"`
}

type Location struct {
	Id				int			`json:"id"`
	Hostname		string		`json:"hostname"`
	Flag			string		`json:"flag"`
	DisplayName		string		`json:"displayName"`
	Tags			[]string	`json:"tags"`
	Geo				Geo			`json:"geo"`
	Children		[]Location	`json:"children"`
}