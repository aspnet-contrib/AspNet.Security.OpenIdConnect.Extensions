AspNet.Security.OAuth.Extensions
================================

**AspNet.Security.OAuth.Extensions** is a collection of **token validation middleware** for ASP.NET Core and OWIN/Katana.

**The latest nightly builds can be found on [MyGet](https://www.myget.org/gallery/aspnet-contrib)**.

[![Build status](https://ci.appveyor.com/api/projects/status/aa7t5nfxpiri1e85/branch/release?svg=true)](https://ci.appveyor.com/project/aspnet-contrib/aspnet-security-oauth-extensions/branch/release)
[![Build status](https://travis-ci.org/aspnet-contrib/AspNet.Security.OAuth.Extensions.svg?branch=release)](https://travis-ci.org/aspnet-contrib/AspNet.Security.OAuth.Extensions)

## Get started

```csharp
app.UseOAuthValidation(options =>
{
    options.Audiences.Add("resource_server");
});
```

```csharp
app.UseOAuthIntrospection(options =>
{
    options.Authority = new Uri("https://openid.yourapp.com/");
    options.Audiences.Add("resource_server");
    options.ClientId = "resource_server";
    options.ClientSecret = "875sqd4s5d748z78z7ds1ff8zz8814ff88ed8ea4z4zzd";
});
```

## Support

**Need help or wanna share your thoughts?** Don't hesitate to join us on Gitter or ask your question on StackOverflow:

- **Gitter: [https://gitter.im/aspnet-contrib/AspNet.Security.OAuth.Extensions](https://gitter.im/aspnet-contrib/AspNet.Security.OAuth.Extensions)**
- **StackOverflow: [https://stackoverflow.com/questions/tagged/aspnet-contrib](https://stackoverflow.com/questions/tagged/aspnet-contrib)**

## Contributors

**AspNet.Security.OAuth.Extensions** is actively maintained by **[Kévin Chalet](https://github.com/PinpointTownes)**. Contributions are welcome and can be submitted using pull requests.

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely. See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.
