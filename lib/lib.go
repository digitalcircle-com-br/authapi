package lib

import (
	"context"
	"net/http"
	"time"

	"github.com/digitalcircle-com-br/service"
	"golang.org/x/crypto/bcrypt"
)

func Run() error {
	service.Init("auth")

	service.HttpHandle("/login", http.MethodPost, "", func(ctx context.Context, in *service.LoginRequest) (out *service.LoginResponse, err error) {
		if in.Tenant == "" {
			in.Tenant = "default"
		}
		db, err := service.DBN(in.Tenant)
		if err != nil {
			return
		}

		ptrTrue := true
		user := &service.SecUser{Username: in.Username, Enabled: &ptrTrue}

		err = db.Preload("Groups.Perms").Find(user).First(user).Error
		if err != nil {
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(user.Hash), []byte(in.Password))
		if err != nil {
			return
		}

		sess := &service.Session{
			Username:  in.Username,
			Perms:     make(map[string]string),
			Tenant:    in.Tenant,
			CreatedAt: time.Now(),
		}

		for _, g := range user.Groups {
			for _, p := range g.Perms {
				sess.Perms[p.Name] = p.Val
			}
		}
		id, err := service.SessionSave(sess)
		ck := http.Cookie{Name: string(service.COOKIE_SESSION), Value: id, Path: "/", Expires: time.Now().Add(time.Hour * 24 * 365 * 10), HttpOnly: true}
		http.SetCookie(service.CtxRes(ctx), &ck)
		return
	})
	service.HttpHandle("/logout", http.MethodGet, "+", func(ctx context.Context, in service.EMPTY_TYPE) (out string, err error) {
		s := service.CtxSessionID(ctx)
		_, err = service.SessionDel(s)
		ck := http.Cookie{Name: string(service.COOKIE_SESSION), Value: "", Path: "/", Expires: time.Now().Add(time.Hour * -1 * 24 * 365 * 10), HttpOnly: true}
		http.SetCookie(service.CtxRes(ctx), &ck)
		return
	})

	service.HttpHandle("/check", http.MethodGet, "+", func(ctx context.Context, in *service.EMPTY_TYPE) (out bool, err error) {
		s := service.CtxSession(ctx)
		if s == nil {
			return false, nil
		}

		return true, nil
	})

	service.HttpHandle("/tenant", http.MethodGet, "+", func(ctx context.Context, in service.EMPTY_TYPE) (out string, err error) {
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
