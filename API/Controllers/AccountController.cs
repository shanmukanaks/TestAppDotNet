using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using DTOs;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseAPIController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService) 
        {
            _tokenService = tokenService;
            _context = context;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDTO>> Register(RegisterDTO dto)
        {

            if ( await UserExists(dto.Username) )
            {
                return BadRequest("Username already taken!");
            } 

            using var hmac = new HMACSHA512();

            var user = new AppUser
            {
                UserName = dto.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(dto.Password)),
                PasswordSalt = hmac.Key
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return new UserDTO
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };

        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDTO>> Login(LoginDTO dto)
        {
            var user = await _context.Users.SingleOrDefaultAsync(user => user.UserName == dto.Username);

            if ( user == null ) return Unauthorized("Username does not exist!");

            using var hmac = new HMACSHA512(user.PasswordSalt);

            var genHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(dto.Password));

            for (var i = 0; i < user.PasswordHash.Length; i++)
            {
                if (genHash[i] != user.PasswordHash[i])
                {
                    return Unauthorized("Password does not match!");
                }
            }

            return new UserDTO
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

        private async Task<bool> UserExists(string Username)
        {
            return await _context.Users.AnyAsync(user => user.UserName == Username.ToLower());
        }
    }
}