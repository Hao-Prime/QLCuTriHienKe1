package com.vnpt.longan.jwt;


import com.vnpt.longan.entity.NguoiDung;
import com.vnpt.longan.reponsitory.NguoiDungReponsitory;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class JwtAuthenticationTokenFilter extends UsernamePasswordAuthenticationFilter{

	private final static String TOKEN_HEADER = "authorization";;
	
	@Autowired
	private JwtService jwtService;

	@Autowired
	private NguoiDungReponsitory userReponsitory;

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		// tách token từ header request
		String bearer = httpRequest.getHeader(TOKEN_HEADER);
		String authToken="";
		if(bearer!=null){
			String[] words= bearer.split("Bearer ");
			authToken=words[words.length-1];
		}
		if (jwtService.validateTokenLogin(authToken)) {

			String password = jwtService.getPasswordFromToken(authToken);
			String id = jwtService.getIDFromToken(authToken);
			NguoiDung user = userReponsitory.timTheoID(id);
			if (user != null && password.equals(user.getPassword())) {
				boolean enabled = true;
				boolean accountNonExpired = true;
				boolean credentialsNonExpired = true;
				boolean accountNonLocked = true;
				List<GrantedAuthority> autho = new ArrayList<GrantedAuthority>();
				for (int i = 0; i < user.getListRoles().size(); i++) {
					//thêm tên quyền cho từng người
					autho.add(new SimpleGrantedAuthority(user.getListRoles().get(i)));
				}
				UserDetails userDetail = new User(user.getHoTen(), user.getPassword(), enabled, accountNonExpired,
						credentialsNonExpired, accountNonLocked, autho);
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetail,
						null, userDetail.getAuthorities());
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpRequest));
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		}
		
		chain.doFilter(request, response);
	}
}
