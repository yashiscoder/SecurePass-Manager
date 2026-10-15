// SecurePass Manager – web edition.
// Your original CLI logic (User, email check, strength rules, file format)
// exposed as a small JSON API plus a static web front end.
//
// Build:  g++ -std=c++17 -O2 -pthread server.cpp -o securepass
// Run:    ./securepass            (then open http://127.0.0.1:8080)

#include "httplib.h"
#include "json.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <regex>
#include <string>
#include <vector>

using namespace std;
using json = nlohmann::json;
namespace fs = std::filesystem;
using Clock = chrono::steady_clock;

/* ------------------------- original data + rules ------------------------- */

struct User
{
    string userName;
    string password;
    string accountName;
};

bool isValidEmail(const string &email)
{
    static const regex valid(R"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)");
    return regex_match(email, valid);
}

static bool isSpecial(unsigned char ch) { return ispunct(ch) != 0; }

string passwordStrengthChecker(const string &password)
{
    bool hasLower = false, hasUpper = false, hasDigit = false, hasSpecial = false;
    bool longEnough = password.length() >= 8;
    for (unsigned char ch : password)
    {
        if (islower(ch)) hasLower = true;
        else if (isupper(ch)) hasUpper = true;
        else if (isdigit(ch)) hasDigit = true;
        else if (isSpecial(ch)) hasSpecial = true;
    }
    int score = hasLower + hasUpper + hasDigit + hasSpecial + longEnough;
    return score >= 5 ? "Strong" : score >= 3 ? "Medium" : "Weak";
}

// Same checks as the original passwordCheck(), returned instead of printed.
vector<string> passwordIssues(const string &p)
{
    vector<string> out;
    auto has = [&](int (*f)(int)) { return any_of(p.begin(), p.end(), [&](unsigned char c) { return f(c) != 0; }); };
    if (!has(isupper)) out.push_back("Add an uppercase letter");
    if (!has(islower)) out.push_back("Add a lowercase letter");
    if (!has(isdigit)) out.push_back("Add a digit");
    if (!any_of(p.begin(), p.end(), [](unsigned char c) { return isSpecial(c); })) out.push_back("Add a special character");
    if (p.length() < 8) out.push_back("Use at least 8 characters");
    return out;
}

/* ------------------------------ vault storage ----------------------------- */

struct Vault
{
    string loginUserName;
    string loginPassword;
    vector<User> users;
    Clock::time_point lastSeen;
};

static const fs::path DATA_DIR = "data";

// Usernames become file names, so they must never contain path characters.
bool validLoginName(const string &s)
{
    if (s.size() < 3 || s.size() > 64 || s[0] == '.' || s.find("..") != string::npos) return false;
    static const string ok = "_.@+-";
    return all_of(s.begin(), s.end(), [](unsigned char c) { return c != 0 && (isalnum(c) || ok.find(char(c)) != string::npos); });
}

// Fields are stored one per line, so they must be single-line.
bool validField(const string &s, size_t maxLen = 256)
{
    return !s.empty() && s.size() <= maxLen && s.find_first_of("\r\n") == string::npos;
}

fs::path vaultPath(const string &name) { return DATA_DIR / (name + ".txt"); }

bool saveVault(const Vault &v)
{
    ofstream f(vaultPath(v.loginUserName), ios::trunc);
    if (!f) return false;
    f << v.loginUserName << "\n" << v.loginPassword << "\n";
    for (const auto &u : v.users) f << u.userName << "\n" << u.password << "\n" << u.accountName << "\n";
    return bool(f);
}

bool loadVault(const string &name, Vault &v)
{
    ifstream f(vaultPath(name));
    if (!f) return false;
    v = Vault{};
    getline(f, v.loginUserName);
    getline(f, v.loginPassword);
    User u;
    while (getline(f, u.userName) && getline(f, u.password) && getline(f, u.accountName)) v.users.push_back(u);
    return !v.loginUserName.empty();
}

/* --------------------------- sessions + throttling ------------------------ */

static mutex M;
static map<string, Vault> sessions;
struct Attempts { int fails = 0; Clock::time_point lockedUntil{}; };
static map<string, Attempts> attempts;
static const auto SESSION_TTL = chrono::minutes(15);

string newToken()
{
    random_device rd;
    static const char *hex = "0123456789abcdef";
    string t;
    for (int i = 0; i < 32; i++) { unsigned b = rd() & 0xff; t += hex[b >> 4]; t += hex[b & 15]; }
    return t;
}

bool sameText(const string &a, const string &b)  // length-independent-ish compare
{
    unsigned diff = a.size() ^ b.size();
    for (size_t i = 0; i < min(a.size(), b.size()); i++) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

Vault *authed(const httplib::Request &req, string *tokenOut = nullptr)
{
    auto h = req.get_header_value("Authorization");
    if (h.rfind("Bearer ", 0) != 0) return nullptr;
    string tok = h.substr(7);
    auto it = sessions.find(tok);
    if (it == sessions.end()) return nullptr;
    if (Clock::now() - it->second.lastSeen > SESSION_TTL) { sessions.erase(it); return nullptr; }
    it->second.lastSeen = Clock::now();
    if (tokenOut) *tokenOut = tok;
    return &it->second;
}

/* --------------------------------- helpers -------------------------------- */

static void reply(httplib::Response &res, int status, const json &body)
{
    res.status = status;
    res.set_content(body.dump(), "application/json");
}
static void fail(httplib::Response &res, int status, const string &msg) { reply(res, status, {{"error", msg}}); }

static bool parseBody(const httplib::Request &req, httplib::Response &res, json &out)
{
    out = json::parse(req.body, nullptr, false);
    if (out.is_discarded() || !out.is_object()) { fail(res, 400, "Invalid request."); return false; }
    return true;
}
static string str(const json &j, const char *k) { return j.contains(k) && j[k].is_string() ? j[k].get<string>() : ""; }

// Original rule: accounts named "gmail"/"email" must use a valid email as username.
static string lower(string s) { for (auto &c : s) c = char(tolower((unsigned char)c)); return s; }

static bool entryIndex(const httplib::Request &req, const Vault &v, size_t &idx)
{
    try { idx = stoul(req.matches[1]); } catch (...) { return false; }
    return idx < v.users.size();
}

/* ----------------------------------- main --------------------------------- */

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 8080;
    fs::create_directories(DATA_DIR);

    httplib::Server svr;
    const string hostA = "127.0.0.1:" + to_string(port), hostB = "localhost:" + to_string(port);

    svr.set_default_headers({
        {"X-Content-Type-Options", "nosniff"},
        {"X-Frame-Options", "DENY"},
        {"Referrer-Policy", "no-referrer"},
        {"Cache-Control", "no-store"},
        {"Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'"},
    });

    // Reject foreign Host headers (blocks DNS-rebinding attacks against the local server).
    svr.set_pre_routing_handler([&](const httplib::Request &req, httplib::Response &res) {
        auto h = req.get_header_value("Host");
        if (h != hostA && h != hostB) { fail(res, 403, "Forbidden host."); return httplib::Server::HandlerResponse::Handled; }
        return httplib::Server::HandlerResponse::Unhandled;
    });

    svr.Post("/api/register", [](const httplib::Request &req, httplib::Response &res) {
        json b; if (!parseBody(req, res, b)) return;
        string name = str(b, "username"), pass = str(b, "password");
        if (!validLoginName(name)) return fail(res, 400, "Username must be 3–64 characters: letters, digits and _ . @ + -");
        if (pass.size() < 8 || !validField(pass)) return fail(res, 400, "Master password must be at least 8 characters.");
        lock_guard<mutex> g(M);
        if (fs::exists(vaultPath(name))) return fail(res, 409, "Username already exists. Please choose a different username.");
        Vault v; v.loginUserName = name; v.loginPassword = pass; v.lastSeen = Clock::now();
        if (!saveVault(v)) return fail(res, 500, "Could not write the vault file.");
        string tok = newToken();
        sessions[tok] = v;
        reply(res, 201, {{"token", tok}, {"username", name}});
    });

    svr.Post("/api/login", [](const httplib::Request &req, httplib::Response &res) {
        json b; if (!parseBody(req, res, b)) return;
        string name = str(b, "username"), pass = str(b, "password");
        lock_guard<mutex> g(M);
        auto &a = attempts[name];
        if (Clock::now() < a.lockedUntil) return fail(res, 429, "Too many attempts. Wait 30 seconds and try again.");
        Vault v;
        if (!validLoginName(name) || !loadVault(name, v) || !sameText(pass, v.loginPassword))
        {
            if (++a.fails >= 5) { a.fails = 0; a.lockedUntil = Clock::now() + chrono::seconds(30); }
            return fail(res, 401, "Incorrect username or password.");
        }
        a = Attempts{};
        v.lastSeen = Clock::now();
        string tok = newToken();
        sessions[tok] = v;
        reply(res, 200, {{"token", tok}, {"username", name}});
    });

    svr.Post("/api/logout", [](const httplib::Request &req, httplib::Response &res) {
        lock_guard<mutex> g(M);
        string tok;
        if (authed(req, &tok)) sessions.erase(tok);
        reply(res, 200, {{"ok", true}});
    });

    svr.Post("/api/strength", [](const httplib::Request &req, httplib::Response &res) {
        json b; if (!parseBody(req, res, b)) return;
        string p = str(b, "password");
        reply(res, 200, {{"strength", passwordStrengthChecker(p)}, {"issues", passwordIssues(p)}});
    });

    svr.Get("/api/entries", [](const httplib::Request &req, httplib::Response &res) {
        lock_guard<mutex> g(M);
        Vault *v = authed(req);
        if (!v) return fail(res, 401, "Session expired. Please sign in again.");
        json list = json::array();
        for (size_t i = 0; i < v->users.size(); i++)
            list.push_back({{"id", i}, {"userName", v->users[i].userName}, {"accountName", v->users[i].accountName},
                            {"strength", passwordStrengthChecker(v->users[i].password)}});
        reply(res, 200, {{"username", v->loginUserName}, {"entries", list}});
    });

    // Passwords are only sent when the user asks to reveal or copy one.
    svr.Get(R"(/api/entries/(\d+)/password)", [](const httplib::Request &req, httplib::Response &res) {
        lock_guard<mutex> g(M);
        Vault *v = authed(req);
        if (!v) return fail(res, 401, "Session expired. Please sign in again.");
        size_t i; if (!entryIndex(req, *v, i)) return fail(res, 404, "User not found.");
        reply(res, 200, {{"password", v->users[i].password}});
    });

    svr.Post("/api/entries", [](const httplib::Request &req, httplib::Response &res) {
        json b; if (!parseBody(req, res, b)) return;
        User u{str(b, "userName"), str(b, "password"), str(b, "accountName")};
        if (!validField(u.userName) || !validField(u.password) || !validField(u.accountName))
            return fail(res, 400, "Username, password and account name are all required.");
        string acct = lower(u.accountName);
        if ((acct == "gmail" || acct == "email") && !isValidEmail(u.userName))
            return fail(res, 400, "Email id is invalid.");
        u.accountName = acct;  // original behaviour: account names are stored lowercase
        lock_guard<mutex> g(M);
        Vault *v = authed(req);
        if (!v) return fail(res, 401, "Session expired. Please sign in again.");
        v->users.push_back(u);
        if (!saveVault(*v)) { v->users.pop_back(); return fail(res, 500, "Could not write the vault file."); }
        reply(res, 201, {{"id", v->users.size() - 1}, {"strength", passwordStrengthChecker(u.password)},
                         {"issues", passwordIssues(u.password)}});
    });

    svr.Put(R"(/api/entries/(\d+))", [](const httplib::Request &req, httplib::Response &res) {
        json b; if (!parseBody(req, res, b)) return;
        string pass = str(b, "password");
        if (!validField(pass)) return fail(res, 400, "Enter a new password.");
        lock_guard<mutex> g(M);
        Vault *v = authed(req);
        if (!v) return fail(res, 401, "Session expired. Please sign in again.");
        size_t i; if (!entryIndex(req, *v, i)) return fail(res, 404, "User not found.");
        v->users[i].password = pass;
        if (!saveVault(*v)) return fail(res, 500, "Could not write the vault file.");
        reply(res, 200, {{"strength", passwordStrengthChecker(pass)}, {"issues", passwordIssues(pass)}});
    });

    svr.Delete(R"(/api/entries/(\d+))", [](const httplib::Request &req, httplib::Response &res) {
        lock_guard<mutex> g(M);
        Vault *v = authed(req);
        if (!v) return fail(res, 401, "Session expired. Please sign in again.");
        size_t i; if (!entryIndex(req, *v, i)) return fail(res, 404, "User not found.");
        v->users.erase(v->users.begin() + i);   // (original looped and erased while iterating)
        if (!saveVault(*v)) return fail(res, 500, "Could not write the vault file.");
        reply(res, 200, {{"ok", true}});
    });

    if (!svr.set_mount_point("/", "./web"))
    {
        cerr << "Could not find the ./web folder. Run the server from the securepass directory.\n";
        return 1;
    }

    cout << "SecurePass is running at http://127.0.0.1:" << port << "  (Ctrl+C to stop)\n";
    if (!svr.listen("127.0.0.1", port)) { cerr << "Could not listen on port " << port << ".\n"; return 1; }
    return 0;
}
