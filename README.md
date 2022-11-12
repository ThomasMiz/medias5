# medias5

The crappiest socks5 proxy you've ever seen ("medias" means "socks" in spanish) 🧦🧦🧦🧦🧦

This project implements a very simple, barebones socks5 proxy server, for educational purposes. The idea is to be able to get a general feel of how this protocol operates without having to read through much code.

This, of course, means this implementation is very simple and limited. For example, it can only handle a single client at a time.

The server opens a passive socket on :::1080 and can handle incoming IPv4 and IPv6 connections. Once connected, it can handle proxy requests for IPv4, IPv6, and domain names.
