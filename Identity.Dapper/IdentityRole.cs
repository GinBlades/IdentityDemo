using Dapper.Contrib.Extensions;
using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;

namespace Identity.OrmLite
{
    [Table("IdentityRole")]
    public class IdentityRole : IRole
    {
        /// <summary>
        ///     Constructor
        /// </summary>
        public IdentityRole()
        {
            Id = Guid.NewGuid().ToString();
        }

        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="roleName"></param>
        public IdentityRole(string roleName)
            : this()
        {
            Name = roleName;
        }

        /// <summary>
        ///     Navigation property for users in the role
        /// </summary>
        [Computed]
        public virtual List<IdentityUserRole> Users { get; private set; } = new List<IdentityUserRole>();

        /// <summary>
        ///     Role id
        /// </summary>
        public string Id { get; set; }

        /// <summary>
        ///     Role name
        /// </summary>
        public string Name { get; set; }
    }
}
