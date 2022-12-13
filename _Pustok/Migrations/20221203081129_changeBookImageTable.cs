using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace _Pustok.Migrations
{
    public partial class changeBookImageTable : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PosterStatus",
                table: "BookImages");

            migrationBuilder.RenameColumn(
                name: "Image",
                table: "BookImages",
                newName: "Name");

            migrationBuilder.AddColumn<bool>(
                name: "Status",
                table: "BookImages",
                type: "bit",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Status",
                table: "BookImages");

            migrationBuilder.RenameColumn(
                name: "Name",
                table: "BookImages",
                newName: "Image");

            migrationBuilder.AddColumn<bool>(
                name: "PosterStatus",
                table: "BookImages",
                type: "bit",
                nullable: false,
                defaultValue: false);
        }
    }
}
