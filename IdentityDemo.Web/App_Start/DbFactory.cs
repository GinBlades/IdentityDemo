using ServiceStack.Data;
using ServiceStack.OrmLite;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;

namespace IdentityDemo.Web
{
    public static class DbFactory
    {
        public static IDbConnectionFactory Connection()
        {
            return new OrmLiteConnectionFactory(
                ConfigurationManager.ConnectionStrings["DefaultConnection"].ConnectionString, SqlServerDialect.Provider);
        }
    }
}