using System.Configuration;
using System.Data.SqlClient;

namespace IdentityDemo.Web
{
    public static class DbFactory
    {
        public static SqlConnection Connection()
        {
            return new SqlConnection(ConfigurationManager.ConnectionStrings["DefaultConnection"].ConnectionString);
        }
    }
}