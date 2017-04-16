using Dapper;
using Dapper.Contrib.Extensions;
using Microsoft.AspNet.Identity;
using System;
using System.Data.SqlClient;
using System.Linq;
using System.Threading.Tasks;

namespace Identity.Dapper
{
    public class RoleStore : IRoleStore<IdentityRole>
    {
        private readonly SqlConnection _conn;

        public RoleStore(SqlConnection conn)
        {
            _conn = conn;
        }

        public async Task CreateAsync(IdentityRole role)
        {
            if (role == null)
            {
                throw new ArgumentNullException("role");
            }
            await _conn.InsertAsync(role);
        }

        public async Task DeleteAsync(IdentityRole role)
        {
            if (role == null)
            {
                throw new ArgumentNullException("role");
            }
            await _conn.DeleteAsync(role);
        }

        public void Dispose()
        {
            _conn.Close();
        }

        public async Task<IdentityRole> FindByIdAsync(string roleId)
        {
            return await _conn.GetAsync<IdentityRole>(roleId);
        }

        public async Task<IdentityRole> FindByNameAsync(string roleName)
        {
            if (roleName == null)
            {
                throw new ArgumentNullException("roleName");
            }
            return await _conn.QuerySingleOrDefaultAsync<IdentityRole>(
                "SELECT * FROM IdentityRole WHERE lower(name) = @roleName", new { RoleName = roleName.ToLower() });
        }

        public async Task UpdateAsync(IdentityRole role)
        {
            if (role == null)
            {
                throw new ArgumentNullException("role");
            }
            await _conn.UpdateAsync(role);
        }
    }
}
