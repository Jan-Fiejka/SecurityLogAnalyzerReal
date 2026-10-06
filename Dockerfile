FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY ["src/SecurityLogAnalyzer.Api/SecurityLogAnalyzer.Api.csproj", "src/SecurityLogAnalyzer.Api/"]
RUN dotnet restore "src/SecurityLogAnalyzer.Api/SecurityLogAnalyzer.Api.csproj"

COPY . .
WORKDIR /src/src/SecurityLogAnalyzer.Api
RUN dotnet publish "SecurityLogAnalyzer.Api.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
COPY --from=build /app/publish .
EXPOSE 10000
ENTRYPOINT ["sh", "-c", "dotnet SecurityLogAnalyzer.Api.dll --urls http://0.0.0.0:${PORT:-10000}"]
