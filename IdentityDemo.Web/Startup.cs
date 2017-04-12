using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(IdentityDemo.Web.Startup))]
namespace IdentityDemo.Web
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            Migrator.Up();
            ConfigureAuth(app);
        }
    }
}
