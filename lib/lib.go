package lib

import (
	"context"
	"net/http"
	"time"

	"github.com/digitalcircle-com-br/random"
	"github.com/digitalcircle-com-br/service"
	"golang.org/x/crypto/bcrypt"
)

func Run() error {
	service.Init("auth")

	service.HttpHandle("/login", http.MethodPost, "", func(ctx context.Context, in *service.LoginRequest) (out *service.LoginResponse, err error) {
		if in.Tenant == "" {
			in.Tenant = "auth"
		}
		db, close, err := service.DBN(in.Tenant)
		if err != nil {
			return
		}
		defer close()
		ptrTrue := true
		user := &service.SecUser{Username: in.Username, Enabled: &ptrTrue}

		err = db.Find(user).First(user).Error
		if err != nil {
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(in.Password), []byte(user.Hash))
		if err != nil {
			return
		}

		id := random.StrTSNano(16)
		service.DataHSet("session."+id, "user", in.Username, "tenant", user.Tenant, "perm.*", "*", "at", time.Now().String())
		ck := http.Cookie{Name: service.COOKIE, Value: id, Path: "/", Expires: time.Now().Add(time.Hour * 24 * 365 * 10), HttpOnly: true}
		http.SetCookie(service.CtxRes(ctx), &ck)
		return
	})
	service.HttpHandle("/logout", http.MethodGet, "", func(ctx context.Context, in service.EMPTY_TYPE) (out string, err error) {
		s := service.CtxSessionID(ctx)
		_, err = service.DataDel(s)
		ck := http.Cookie{Name: service.COOKIE, Value: "", Path: "/", Expires: time.Now().Add(time.Hour * -1 * 24 * 365 * 10), HttpOnly: true}
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
