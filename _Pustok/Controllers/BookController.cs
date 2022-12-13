using _Pustok.DAL;
using _Pustok.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace _Pustok.Controllers
{
    public class BookController : Controller
    {
        private readonly PustokContext _context;
        public BookController(PustokContext context)
        {
            _context = context;
        }
        public IActionResult GetBook(int id)
        {
            Book book = _context.Books.Include(x => x.Genre).Include(x => x.BookImages).FirstOrDefault(x => x.Id == id);

            
            return PartialView("_BookModalPartial", book);
        }
        public IActionResult Detail(int id)
        {
            Book book = _context.Books.Include(x => x.Genre).Include(x => x.BookImages).FirstOrDefault(x => x.Id == id);

            return View(book);
        }

    }
}
