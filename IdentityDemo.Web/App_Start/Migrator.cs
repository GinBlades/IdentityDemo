using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ServiceStack.Data;
using ServiceStack.OrmLite;
using Identity.OrmLite;
using IdentityDemo.Web.Models;

namespace IdentityDemo.Web
{
    public static class Migrator
    {
        public static void Up()
        {
            using (var db = DbFactory.Connection().Open())
            {
                db.CreateTableIfNotExists<ApplicationUser>();
                db.CreateTableIfNotExists<IdentityRole>();
                db.CreateTableIfNotExists<IdentityUserClaim>();
                db.CreateTableIfNotExists<IdentityUserLogin>();
                db.CreateTableIfNotExists<IdentityUserRole>();
            }
        }
    }
}
