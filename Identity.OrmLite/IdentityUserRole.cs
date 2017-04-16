using ServiceStack.DataAnnotations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Identity.Dapper
{
    public class IdentityUserRole : IUserRelationship
    {
        [AutoIncrement]
        public int Id { get; set; }
        /// <summary>
        ///     UserId for the user that is in the role
        /// </summary>
        public virtual string UserId { get; set; }

        /// <summary>
        ///     RoleId for the role
        /// </summary>
        public virtual string RoleId { get; set; }
    }
}
