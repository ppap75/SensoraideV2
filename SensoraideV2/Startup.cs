using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(SensoraideV2.Startup))]
namespace SensoraideV2
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
