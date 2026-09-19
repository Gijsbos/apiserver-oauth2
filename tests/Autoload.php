<?php
declare(strict_types=1);

use gijsbos\ApiServer\Cors;
use gijsbos\ApiServer\OAuth2\Components\AccessTokenVerificationPolicy;
use gijsbos\ApiServer\OAuth2\OAuth2Server;
use gijsbos\ApiServer\Parsers\RouteParser;
use gijsbos\ApiServer\SecurityContext;
use gijsbos\ExtFuncs\Utils\DotEnv;

use Jose\Component\Core\JWK;

include_once "vendor/autoload.php";

include_once "tests/Files/TestController.php";
include_once "tests/Files/JwtFactory.php";

RouteParser::run();

DotEnv::parse();

// Define example key set
define("EXAMPLE_KEY_SET", new JWK([
    'kid' => 'b919b9cb70816003dd29a3ce3eca4a5e26b47353',
    'alg' => 'RS256',
    'use' => 'sig',
    'kty' => 'RSA',
    'n' => 'zATP5eJ-QFeRDySEpFwMypkz6Oa_Mb2B56HlMHZLoxINYxnkrJYI7KFWfB8TvojSA1MuzorimD-vzj88x2a82S3IZBaKaJHFuyT-kwF_UdXmo1UvwQfDyXtgJ2efDR3B9SU5vcN4uUxddZzWO00Bkbe-eVcDJLUNro7h77jJd9HYkgwx_vZI7WwKHxZc3B8oypNNk7ss2nmxSiRKJnTEG5XKSYqO9XVcllUh1kcVDT4sm9OSMpB_Cu30VPEUIV_OpsAqaSQxiF6W3FIoTC1KSaLL9H3HPtLEAjOARFCIMonmwOJlzpd_uI5LGfHqnLkbGyCPRvJs7Ts8LoWFV9Ru3Q',
    'e' => 'AQAB',
    'd' => 'Xz6p3f0AisI2ptaaE-8jS5v9N3At9yctE7mpeRfo1L7TQB4w-v9qOCpT6UtK2Osf_ExjsCn3gjNNPGCaW87TQCKXCF7bi9jt8iHhtTiAO3C8JSlaS2f4F8JAz_SYtLNdPrh7veMZI4yKnyMygmm_X0tkIVqlTYg21HTA9rySVZxrx3JVHYPg7ZLEdIYNHKsG9ZhFmyIN_fk8tsUIV_RHTK79yXKiEY0fXWBZGXsFE7nqZWMSupzDVnPJYhlXxxGUfr636yO2SZqtyURcOwvS2xToJDb9F3FHX8SLc7DLk2VgGGRd2uTv8ODbbfupUrSajSjFitsgPUlOrK-_xehcYw',
    'p' => '_ffBCLWZPf4mZoK4KIKaoudf5wxZkTzz1E_7p9o_Qiny-dANjbt_J6Qc5JFH8QSuuZfUqB8j9HaZBPk0qF3zG6Y_SRlhmjYfg4wzyHFGOL1FL4nZbbthfbG5e2RvNx0MaUfyyq0RTFAQSJsq8_m-PFrpcVlMIoKLn_A3gpj7Ifc',
    'q' => 'zaa9KyuknusKbqgBu5ZtBLI86H9-ak2AN8ltA6rbtl-UQoD9ffa3f8yutQgD4m6kCkBBxIWqjSecZ7ntqcg5cwcJVgCYtrIfazyFdow-8kOTqmwdEMTq0IliCFHizcq7xID-coj7lQJp3gHLgAYR1PV-xbUMRieEfXTGsAizgMs',
    'dp' => 'Kga-pc9PTYfqGNqW2PVL25tILnbHt5YLj12w-kTOZQeGErrQE10snIW21kgITKUGuOWcJjoI_CJIDh-jDB2H5lJrdJBDq347VsxzoT7FbQw9D7HTDiqM5nzrgbTMBqXC8QUb81gSXbt-BlXPFNKGHXy51qz9QVSzAEODHBRusl8',
    'dq' => 'WjAGg9k27666O38Yi3DTzJxyE7Bd-zaTxWNjmJkkk91kwqmZAdXh8X0NHT0vnuzQqeI2NX49Jnw5nk-ux6eUcjqiwIGwd2a0Wq4HBc9Jh6tVJgcV1BXXuK6XPHjU01VWdT3w2L_0PQv6666z1ShUR6WF_CSDBn0sIGzG-cpHFnM',
    'qi' => 'uTs7N39yehXvv72crSTLOuSNDFGD2t3NFZyKRypT2ZYEURvRoydqEZwd8vk6vXt7gKabeyy20IHZEqwM8v9zVjWifMb_TCLJ_s7_sF3v987HNTT-9GIRLqXg8FrexQ2HIWgO96m2qZtv1Axhb3Xejjx4nIUpdGbBd73SpLpRA98',
]));

// The verifiers behind #[HasScope] / #[HasRole] read the result SecurityContext produces when it
// authenticates the request, so every path with an authority attribute must require auth. Paths
// that match no rule require auth, so only the public routes and the test IdP are permitted.
OAuth2Server::$securityContext = new SecurityContext()->permitAll("/test/public", "/test/idp/**");

// Cors::handle() is a no-op until at least one origin is set here.
OAuth2Server::$cors = new Cors();