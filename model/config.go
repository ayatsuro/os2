package model

type PluginConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Url      string `json:"url"`
	SkipSsl  bool   `json:"skip_ssl"`
}
