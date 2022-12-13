
using _Pustok.DAL;
using _Pustok.Models;
using _Pustok.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;
using System.Linq;

namespace _Pustok.Controllers
{
    public class HomeController : Controller
    {
        private readonly PustokContext _context;

        public HomeController(PustokContext context)
        {
            _context = context;
        }


        public IActionResult Index()
        {

            HomeViewModel homeVM = new HomeViewModel
            {
                SpecialBooks = _context.Books.Include(x => x.Author).Include(x => x.BookImages).Where(x => x.IsSpecial).Take(20).ToList(),
                NewBooks = _context.Books.Include(x => x.Author).Include(x => x.BookImages).Where(x => x.IsNew).Take(20).ToList(),
                DiscountedBooks = _context.Books.Include(x => x.Author).Include(x => x.BookImages).Where(x => x.DiscountPercent > 0).Take(20).ToList(),
                Sliders = _context.Sliders.OrderBy(x => x.Order).ToList(),
                Settings = _context.Settings.ToDictionary(x => x.Key, x => x.Value),
                Features = _context.Features.ToList()
            };
            return View(homeVM);
        }
      

    }
}