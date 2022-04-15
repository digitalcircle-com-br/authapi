package lib

import (
	"context"
	"net/http"
	"time"

	"github.com/digitalcircle-com-br/random"
	"github.com/digitalcircle-com-br/service"
)

const COOKIE = "X-SESSIONID"

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
}

func Run() error {
	service.Init("auth")
	//db, err := service.DBN("auth")
	// if err != nil {
	// 	return err
	// }
	service.HttpHandle("/login", http.MethodPost, "", func(ctx context.Context, in *LoginRequest) (out *LoginResponse, err error) {

		id := random.StrTSNano(16)
		service.DataHSet(id, "user", in.Username, "tenant", "default", "*", "*")
		ck := http.Cookie{Name: COOKIE, Value: id, Path: "/", Expires: time.Now().Add(time.Hour * 24 * 365 * 10), HttpOnly: true}
		http.SetCookie(service.CtxRes(ctx), &ck)
		return
	})
	service.HttpHandle("/logout", http.MethodGet, "", func(ctx context.Context, in service.EMPTY_TYPE) (out string, err error) {
		s := service.CtxSessionID(ctx)
		_, err = service.DataDel(s)
		ck := http.Cookie{Name: COOKIE, Value: "", Path: "/", Expires: time.Now().Add(time.Hour * -1 * 24 * 365 * 10), HttpOnly: true}
		http.SetCookie(service.CtxRes(ctx), &ck)
		return
	})

	service.HttpHandle("/check", http.MethodGet, "", func(ctx context.Context, in service.EMPTY_TYPE) (out bool, err error) {
		s := service.CtxSessionID(ctx)
		if s == "" {
			return false, nil
		}

		smap, err := service.DataHGetAll(s)

		if err != nil {
			return false, nil
		}
		if len(smap) < 1 {
			return false, nil
		}
		return true, nil
	})

	service.HttpHandle("/tenant", http.MethodGet, "", func(ctx context.Context, in service.EMPTY_TYPE) (out string, err error) {
		s := service.CtxSessionID(ctx)
		if s == "" {
			return "", nil
		}
		smap, err := service.DataHGetAll(s)

		if err != nil {
			return "", nil
		}
		if len(smap) < 1 {
			return "", nil
		}
		return smap["tenant"], nil
	})
	service.HttpRun("")
	return nil

}
