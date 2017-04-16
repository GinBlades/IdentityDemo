using Microsoft.AspNet.Identity;
using ServiceStack.Data;
using ServiceStack.OrmLite;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Identity.Dapper
{
    public class RoleStore : IRoleStore<IdentityRole>
    {
        private readonly IDbConnectionFactory _conn;

        public RoleStore(IDbConnectionFactory conn)
        {
            _conn = conn;
        }

        public Task CreateAsync(IdentityRole role)
        {
            if (role == null)
            {
                throw new ArgumentNullException("role");
            }
            using (var db = _conn.Open())
            {
                return db.InsertAsync(role);
            }
        }

        public Task DeleteAsync(IdentityRole role)
        {
            if (role == null)
            {
                throw new ArgumentNullException("role");
            }
            using (var db = _conn.Open())
            {
                return db.DeleteAsync(role);
            }
        }

        public void Dispose()
        {
            // Nothing to dispose?
        }

        public Task<IdentityRole> FindByIdAsync(string roleId)
        {
            using (var db = _conn.Open())
            {
                return db.SingleByIdAsync<IdentityRole>(roleId);
            }
        }

        public Task<IdentityRole> FindByNameAsync(string roleName)
        {
            using (var db = _conn.Open())
            {
                return db.SingleAsync<IdentityRole>(ir => ir.Name.ToUpper() == roleName.ToUpper());
            }
        }

        public Task UpdateAsync(IdentityRole role)
        {
            if (role == null)
            {
                throw new ArgumentNullException("role");
            }
            using (var db = _conn.Open())
            {
                return db.UpdateAsync(role);
            }
        }
    }
}
