using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using StatusCode.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace StatusCode.Controllers
{
    [Route("v1/[controller]")]
    [ApiController]
    public class UsuarioController : ControllerBase
    {
        private SistemaContext DbSistema = new SistemaContext();

        [HttpPost]
        [Route("Cadastrar")]
        [AllowAnonymous]
        public ActionResult CadastrarUsuario(Usuario usuario)
        {
            DbSistema.Usuario.Add(usuario);
            DbSistema.SaveChanges();
            if (usuario != null)
            {
                return Ok();
            }
            else
            {
                return BadRequest("Informacoes incompativeis com o solicitado");
            }

        }

        [HttpPost]
        [Route("Autenticar")]
        [AllowAnonymous]
        public ActionResult<dynamic> Autenticar(Credencial credencial)
        {
            // 1. Buscar um usuário que tenha o mesmo username
            var usuario = DbSistema.Usuario.Where(Usuario => Usuario.Username == credencial.Username && Usuario.Senha == credencial.Senha).FirstOrDefault();

            if (usuario != null)
            {
                usuario.Senha = null;
                var chaveToken = GerarChaveToken();

                // 3.2. Retorno o Token.

                return Created("Autenticado", new { usuario, token = chaveToken });

            }
            // 2. Se usuário não for encontrado retorno Usuário ou Senha incorretos.
            return NotFound(new { menseger = "Usuário ou senha incorretos." });

        }

        [HttpGet]
        [Route("Usuarios")]
        [Authorize]
        public ActionResult<List<Usuario>> ListaUsuarios()
        {
            return Ok(DbSistema.Usuario.ToList());
        }
       

        private static string GerarChaveToken()
        {
            var jwt = new JwtSecurityTokenHandler();

            // 1. Implementar o Corpo/Payload do Token
            var payload = new SecurityTokenDescriptor
            {
                Expires = DateTime.UtcNow.AddHours(1),
                // 1.1. Implementar a Assinatura.
                SigningCredentials = new SigningCredentials(
                    // 1.1.1. Chave secreta que será utilizada para Criptografia. 
                    new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Ambiente.ChaveSecreta)),
                    // 1.1.2. Algorítimo de Criptografia.
                    SecurityAlgorithms.HmacSha256)
            };

            // 2. Crio a Chave Token
            var chaveToken = jwt.CreateToken(payload);

            // 3. Retorno a Chave Token
            return jwt.WriteToken(chaveToken);
        }

    }
}



