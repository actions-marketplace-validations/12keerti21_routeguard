package apis

import (
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
)

func bindSettingsApi(app core.App, rg *router.RouterGroup[*core.RequestEvent]) {
	sub := rg.Group("/settings").Bind(RequireSuperuserAuth())
	sub.GET("", settingsList)
	sub.POST("/test/email", settingsTestEmail)
	rg.GET("/backups", backupsList).Bind(RequireSuperuserAuth())
	rg.GET("/health", health)
}

func RequireSuperuserAuth() *hook.Handler[*core.RequestEvent] { return nil }
func settingsList(e *core.RequestEvent) error                { return nil }
func settingsTestEmail(e *core.RequestEvent) error           { return nil }
func backupsList(e *core.RequestEvent) error                 { return nil }
func health(e *core.RequestEvent) error                      { return nil }
