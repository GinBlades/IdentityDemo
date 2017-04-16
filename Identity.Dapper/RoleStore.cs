using Dapper;
using Dapper.Contrib.Extensions;
using Microsoft.AspNet.Identity;
using System;
using System.Threading.Tasks;

namespace Identity.Dapper
{
    public class RoleStore : IRoleStore<IdentityRole>
    {
        private readonly IConnectionFactory _conn;

        public RoleStore(IConnectionFactory conn)
        {
            _conn = conn;
        }

        public async Task CreateAsync(IdentityRole role)
        {
            if (role == null)
            {
                throw new ArgumentNullException("role");
            }
            using (var db = _conn.Get())
            {
                await db.InsertAsync(role);
            }
        }

        public async Task DeleteAsync(IdentityRole role)
        {
            if (role == null)
            {
                throw new ArgumentNullException("role");
            }
            using (var db = _conn.Get())
            {
                await db.DeleteAsync(role);
            }
        }

        public void Dispose()
        {
            // Nothing to dispose
        }

        public async Task<IdentityRole> FindByIdAsync(string roleId)
        {
            using (var db = _conn.Get())
            {
                return await db.GetAsync<IdentityRole>(roleId);
            }
        }

        public async Task<IdentityRole> FindByNameAsync(string roleName)
        {
            if (roleName == null)
            {
                throw new ArgumentNullException("roleName");
            }
            using (var db = _conn.Get())
            {
                return await db.QuerySingleOrDefaultAsync<IdentityRole>(
                    "SELECT * FROM IdentityRole WHERE lower(name) = @roleName", new { RoleName = roleName.ToLower() });
            }
        }

        public async Task UpdateAsync(IdentityRole role)
        {
            if (role == null)
            {
                throw new ArgumentNullException("role");
            }
            using (var db = _conn.Get())
            {
                await db.UpdateAsync(role);
            }
        }
    }
}
