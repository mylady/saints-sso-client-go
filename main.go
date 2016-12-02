package saints_sso_client

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	_ "github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
)

const (
	ClientPassed = "SSOClient"
)

type SSOUser struct {
	PublicUserId string `json:"public_user_id"`
	UserName     string `json:"user_name"`
	UserPwd      string `json:"user_pwd"`
	NickName     string `json:"nick_name"`
	Avatar       string `json:"avatar"`
	Wechat       string `json:"wechat"`
	Email        string `json:"emial"`
	Mobile       string `json:"mobile"`
	RealName     string `json:"real_name"`
	IdNumber     string `json:"id_number"`
}

type SSOPermit struct {
	ClientId       string `json:"client_id"`
	PermissionCode string `json:"permission_code"`
	IsPermitted    bool   `json:"is_permitted"`
}

type SSOClient struct {
	Config         *SSOConfig
	authBase       string
	authValidate   string
	authResource   string
	authService    string
	authProxyLogin string
	authProxyToken string
	userInfo       string
	permCheck      string
	nativeLogin    bool
	loginUri       string
	ssoLoginUri    string
	logoutUri      string
	loginPath      string
}

func (this *SSOClient) init() {
	if this.Config != nil {
		this.authBase = fmt.Sprintf("http://%s:%d/oauth", this.Config.AuthHost, this.Config.AuthPort)
		this.authValidate = this.authBase + "/v"
		this.authResource = this.authBase + "/p"
		this.authService = this.authBase + "/s"
		this.authProxyLogin = this.authBase + "/proxylogin"
		this.authProxyToken = this.authBase + "/proxylogin/proxytoken"
		this.userInfo = this.authResource + "/userinfo"
		this.permCheck = this.authResource + "/clientperm"
		this.loginUri = this.Config.LoginUri
		this.nativeLogin = this.Config.LoginUri != ""
		this.ssoLoginUri = this.authBase + "/login?client_id=" + this.Config.ClientId + "&redirect_uri=" + this.Config.RedirectUri
		this.logoutUri = this.authBase + "/logout"
		if this.Config.LoginUri != "" {
			if uri, err := url.Parse(this.Config.LoginUri); err == nil {
				this.loginPath = uri.Path
			}
		}
	}
}

type SSOConfig struct {
	AuthHost     string
	AuthPort     int
	ClientId     string
	ClientSecret string
	LoginUri     string
	RedirectUri  string
	FilterPaths  []string
}

func NewSSOClient(config SSOConfig) (client *SSOClient, err error) {
	if config.AuthHost == "" {
		err = errors.New("Need auth service host")
	} else if config.AuthPort < 80 {
		err = errors.New("Need valid auth port")
	} else if config.ClientId == "" {
		err = errors.New("Need register client id")
	} else if config.ClientSecret == "" {
		err = errors.New("Need register client secret key")
	} else if len(config.FilterPaths) == 0 {
		err = errors.New("Need at least on path to filter")
	} else {
		client = &SSOClient{
			Config: &config,
		}
		client.init()
	}
	return client, err
}

func (this *SSOClient) HijackRequest(ctx *context.Context) {
	ctx.Input.SetData(ClientPassed, this)
	if ctx.Input.URL() == "/" && strings.Index(ctx.Input.URI(), "&") < 0 {
		if ctx.Input.Query("code") != "" && ctx.Input.Query("err") == "" {
			getToken(this, ctx)
		} else if ctx.Input.Query("token") != "" {
			ctx.Input.CruSession.Set("token", ctx.Input.Query("token"))
			ctx.Redirect(302, this.Config.RedirectUri)
		} else {
			if ssotoken, err := parseToken(ctx); err == nil {
				if err := validateToken(this, ssotoken); err != nil {
					ctx.Input.CruSession.Set("token", "")
					getCode(this, ctx, err)
				}
			} else {
				getCode(this, ctx, err)
			}
		}
	} else if this.loginPath != "" && ctx.Input.URL() == this.loginPath {
		if ssotoken, err := parseToken(ctx); err == nil {
			if err := validateToken(this, ssotoken); err != nil {
				ctx.Input.CruSession.Set("token", "")
				if this.nativeLogin {
					ctx.Redirect(302, this.loginUri)
				} else {
					ctx.Redirect(302, this.ssoLoginUri)
				}
			} else {
				ctx.Redirect(302, this.Config.RedirectUri)
			}
		} else {
			if !this.nativeLogin {
				ctx.Redirect(302, this.ssoLoginUri)
			}
		}
	} else {
		needFilter := false
		if len(this.Config.FilterPaths) == 1 && this.Config.FilterPaths[0] == "*" {
			needFilter = true
		} else {
			for _, path := range this.Config.FilterPaths {
				if strings.Index(ctx.Input.URL(), path) >= 0 {
					needFilter = true
					break
				}
			}
		}

		if needFilter {
			if ssotoken, err := parseToken(ctx); err == nil {
				if err := validateToken(this, ssotoken); err != nil {
					ctx.Input.CruSession.Set("token", "")
					getCode(this, ctx, err)
				}
			} else {
				getCode(this, ctx, err)
			}
		}
	}
}

func (this *SSOClient) GetUserInfo(ctx *context.Context) (data []byte, err error) {
	var ssotoken string
	if ssotoken, err = parseToken(ctx); err == nil {
		data, err = get(this.userInfo + "?access_token=" + ssotoken)
	}
	return data, err
}

func (this *SSOClient) CheckClientPermission(ctx *context.Context) (data []byte, err error) {
	var ssotoken string
	clientid := ctx.Input.Query("client_id")
	permissioncode := ctx.Input.Query("permission_code")
	if ssotoken, err = parseToken(ctx); err == nil {
		data, err = get(this.permCheck + "?access_token=" + ssotoken + "&client_id=" + clientid + "&permission_code=" + permissioncode)
	}
	return data, err
}

func (this *SSOClient) Logout(ctx *context.Context) (err error) {
	var ssotoken string
	if ssotoken, err = parseToken(ctx); err == nil {
		if _, err = get(this.logoutUri + "?access_token=" + ssotoken); err == nil {
			ctx.Input.CruSession.Set("token", "")
			if this.nativeLogin {
				ctx.Redirect(302, this.loginUri)
			} else {
				ctx.Redirect(302, this.ssoLoginUri)
			}
		}
	}
	return err
}

func getCode(client *SSOClient, ctx *context.Context, err error) {
	var loginUri string
	if client.nativeLogin {
		loginUri = client.loginUri
	} else {
		loginUri = client.ssoLoginUri
	}
	query := fmt.Sprintf("client_id=%s&redirect_uri=%s&login_uri=%s",
		client.Config.ClientId, client.Config.RedirectUri, url.QueryEscape(loginUri))

	if ctx.Input.IsAjax() {
		ctx.Output.Status = 403
		ctx.Output.JSON(err, false, true)
	} else {
		ctx.Redirect(302, client.authProxyLogin+"?"+query)
	}
}

func getToken(client *SSOClient, ctx *context.Context) {
	query := fmt.Sprintf("grant_type=authorization_code&code=%s&client_id=%s&client_secret=%s&redirect_uri=%s",
		ctx.Input.Query("code"), client.Config.ClientId, client.Config.ClientSecret, url.QueryEscape(client.Config.RedirectUri))
	ctx.Redirect(302, client.authProxyToken+"?"+query)
}

func parseToken(ctx *context.Context) (ssotoken string, err error) {
	sessiontoken := ctx.Input.CruSession.Get("token")
	if sessiontoken == nil {
		err = errors.New("not authorized")
	} else {
		ok := false
		if ssotoken, ok = sessiontoken.(string); !ok {
			err = errors.New("not valid token")
		} else {
			if ssotoken == "" {
				err = errors.New("not authorized")
			}
		}
	}

	if err != nil {
		fmt.Printf("parse token error is %s\r\n", err.Error())
	}

	return ssotoken, err
}

func validateToken(client *SSOClient, token string) (err error) {
	url := client.authValidate + "?access_token=" + token
	_, err = get(url)
	if err != nil {
		fmt.Printf("validate token err is %s\r\n", err.Error())
	}
	return err
}

func get(url string) (data []byte, err error) {
	var response *http.Response
	if response, err = http.Get(url); err == nil {
		if data, err = ioutil.ReadAll(response.Body); err == nil {
			if response.StatusCode != http.StatusOK {
				data = make([]byte, 0)
				err = errors.New(string(data))
			}
		}
	}
	return data, err
}
