using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Vyshyvanka.Engine.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddHasChangedPasswordToUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "HasChangedPassword",
                table: "Users",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "HasChangedPassword",
                table: "Users");
        }
    }
}
