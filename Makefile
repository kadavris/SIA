#PREFIX = /tmp
USER = smarthome
GROUP = smarthome
DESTDIR = /etc/smarthome/ajax
FILES_EXE = ajax_service.pl
FILES_PLAIN = ajax_service.config.example
FILES_SVC = ajax_service.service
SVC = ajax_service
SVCDEST = /etc/systemd/system
INSTPARMS = -D --verbose --compare --group=$(GROUP) --owner=$(USER)
MODE_PLAIN = ug=r,o-rwx
MODE_EXE = ug=rx,o-rwx

.PHONY: install
install: $(FILES_EXE) $(FILES_PLAIN) $(FILES_SVC) install_exe install_plain install_svc

.PHONY: install_exe
install_exe: $(FILES_EXE)
	install $(INSTPARMS) --target-directory="$(PREFIX)$(DESTDIR)" --mode=$(MODE_EXE) $(FILES_EXE)

.PHONY: install_plain
install_plain: $(FILES_PLAIN)
	install $(INSTPARMS) --target-directory="$(PREFIX)$(DESTDIR)" --mode=$(MODE_PLAIN) $(FILES_PLAIN)

.PHONY: install_svc
install_svc: $(FILES_SVC)
	install $(INSTPARMS) --target-directory="$(SVCDEST)" --mode=ug=rw,o-rwx --mode=$(MODE_PLAIN) --owner=root $(FILES_SVC)
	systemctl daemon-reload
	for s in $(SVC); do if systemctl is-active $$s; then systemctl restart $$s; else echo "Do not forget to (re)start $$s"; fi; done

.PHONY: uninstall
uninstall:
	rm -f $(PREFIX)$(DESTDIR)/$(FILES_EXE)
	rm -f $(PREFIX)$(DESTDIR)/$(FILES_PLAIN)
	rm -f $(PREFIX)$(SVCDEST)/$(FILES_SVC)
