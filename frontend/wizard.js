(() => {
  const ADMIN_STEPS = ["Typ dostępu", "Informacje podstawowe", "Konfiguracja połączenia", "Uwierzytelnianie i sekrety", "Uprawnienia użytkownika", "Nagrywanie i bezpieczeństwo", "Użytkownicy i grupy", "Akceptacja i czas dostępu", "Test połączenia", "Podsumowanie i utworzenie"];
  const REQUEST_STEPS = ["Zasób", "Profil dostępu", "Czas dostępu", "Uzasadnienie i wysłanie"];
  const clone = (value) => JSON.parse(JSON.stringify(value));
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));

  const wizard = {
    root: null, mode: null, resourceType: null, preset: null, step: 0, draftId: null,
    data: {}, presets: {}, secretInputs: {}, checks: [], discovery: null, pickerRole: "username", saveTimer: null,

    async open() {
      const pam = window.PAM; if (!pam) return;
      this.reset();
      this.root = document.createElement("section"); this.root.id = "accessWizard"; this.root.className = "access-wizard";
      document.body.appendChild(this.root); document.body.classList.add("wizard-open");
      try { this.presets = await pam.api("/api/access-wizard/presets"); } catch (_) { this.presets = {}; }
      if (pam.state().user.role !== "admin") { this.mode = "request_access"; this.step = 1; await this.ensureDraft(); }
      this.render();
    },

    reset() { this.mode = this.resourceType = this.preset = null; this.step = 0; this.draftId = null; this.data = {}; this.secretInputs = {}; this.checks = []; this.discovery = null; this.pickerRole = "username"; },
    close() { clearTimeout(this.saveTimer); this.root?.remove(); this.root = null; document.body.classList.remove("wizard-open"); this.secretInputs = {}; },
    get steps() { return this.mode === "request_access" ? REQUEST_STEPS : ADMIN_STEPS; },
    get pam() { return window.PAM; },
    field(path, fallback = "") { let value = this.data; for (const part of path.split(".")) value = value?.[part]; return value ?? fallback; },
    set(path, value) { const parts = path.split("."); let target = this.data; parts.slice(0, -1).forEach((part) => target = target[part] ??= {}); target[parts.at(-1)] = value; },

    async chooseMode(mode) {
      this.mode = mode; this.step = 1;
      if (mode === "create_resource") this.data = {resource:{environment:"prod",criticality:"medium",enabled:true,tags:[]},connection:{},access_profile:{allowed_durations:[30,60]},policy:{},assignments:[]};
      else this.data = {assignments:[],policy:{maximum_duration_minutes:60},access_profile:{allowed_durations:[30,60]}};
      await this.ensureDraft(); this.render();
    },

    async choosePreset(key) {
      const preset = clone(this.presets[key] || {}); this.preset = key; this.resourceType = preset.resource_type || this.resourceType;
      this.data.connection = {...preset.connection}; this.data.policy = {...preset.policy};
      this.data.access_profile = {name:"",description:"",access_option:preset.access_option || "ssh_only",allowed_durations:[30,60]};
      await this.save(); this.render();
    },

    async ensureDraft() {
      if (this.draftId) return;
      const result = await this.pam.api("/api/access-wizard/drafts", {method:"POST", body:JSON.stringify({mode:this.mode,resource_type:this.resourceType,data:this.data})});
      this.draftId = result.id;
    },

    safeData() { return clone(this.data); },
    scheduleSave() { clearTimeout(this.saveTimer); this.saveTimer = setTimeout(() => this.save().catch((error) => this.showError(error.message)), 450); this.setSaveStatus("Zapisywanie…"); },
    async save() {
      await this.ensureDraft();
      await this.pam.api(`/api/access-wizard/drafts/${this.draftId}`, {method:"PATCH", body:JSON.stringify({mode:this.mode,resource_type:this.resourceType,data:this.safeData(),completed_steps:Array.from({length:Math.max(0,this.step-1)},(_,i)=>i+1)})});
      this.setSaveStatus("Zapisano bez sekretów");
    },

    setSaveStatus(text) { const node = this.root?.querySelector("#wizardSave"); if (node) node.textContent = text; },
    showError(message, errors = []) { const node = this.root?.querySelector("#wizardErrors"); if (!node) return; node.innerHTML = `<div class="alert alert-danger"><strong>${esc(message)}</strong>${errors.length ? `<ul>${errors.map((e)=>`<li>${esc(e.message)}</li>`).join("")}</ul>` : ""}</div>`; node.scrollIntoView({behavior:"smooth",block:"nearest"}); },

    header() {
      const progress = this.steps.map((name, index) => `<button type="button" class="wizard-step ${index+1===this.step?"active":""} ${index+1<this.step?"done":""}" data-jump="${index+1}" ${index+1>this.step?"disabled":""}><span>${index+1}</span><small>${esc(name)}</small></button>`).join("");
      return `<header class="wizard-top"><button class="btn btn-outline-secondary" data-wizard="close"><i class="bi bi-x-lg"></i> Zamknij</button><div><h1>Nowy dostęp</h1><small id="wizardSave">${this.draftId?"Draft zapisany":"Wybierz scenariusz"}</small></div></header>${this.step ? `<nav class="wizard-progress">${progress}</nav>` : ""}`;
    },

    render() {
      if (!this.root) return;
      this.root.innerHTML = `${this.header()}<main class="wizard-main"><div id="wizardErrors"></div>${this.step ? this.stepContent() : this.modeContent()}</main>${this.step ? this.footer() : ""}`;
      this.bind();
    },

    modeContent() {
      return `<div class="wizard-intro"><p class="eyebrow">Wybierz cel</p><h2>Co chcesz skonfigurować?</h2><div class="scenario-grid"><button class="scenario-card" data-mode="create_resource"><i class="bi bi-hdd-network"></i><strong>Udostępnij nowy zasób</strong><span>Utwórz SSH lub WWW, połączenie, zasady i przydziały.</span></button><button class="scenario-card" data-mode="assign_existing_resource"><i class="bi bi-person-check"></i><strong>Przydziel dostęp do istniejącego zasobu</strong><span>Dodaj profil albo przypisz istniejący profil użytkownikom.</span></button></div></div>`;
    },

    stepContent() {
      if (this.mode === "request_access") return this.requestContent();
      if (this.mode === "assign_existing_resource" && this.step === 1) return this.existingResourceStep();
      if (this.mode === "assign_existing_resource" && this.step === 2) return this.existingOverviewStep();
      if (this.mode === "assign_existing_resource" && this.step === 3) return `<section class="wizard-panel"><div class="wizard-section-title"><span>Krok 3 z 10</span><h2>Konfiguracja połączenia</h2></div><div class="alert alert-info">Kreator nie zmieni połączenia istniejącego zasobu. Możesz przejść dalej do nowego profilu dostępu.</div></section>`;
      if (this.mode === "assign_existing_resource" && this.step === 4) return `<section class="wizard-panel"><div class="wizard-section-title"><span>Krok 4 z 10</span><h2>Uwierzytelnianie i sekrety</h2></div><div class="alert alert-info">Sekrety istniejącego zasobu pozostają bez zmian i nie są odczytywane przez kreator.</div></section>`;
      const renderers = [()=>this.presetStep(),()=>this.basicStep(),()=>this.connectionStep(),()=>this.authStep(),()=>this.permissionsStep(),()=>this.securityStep(),()=>this.assignmentsStep(),()=>this.approvalStep(),()=>this.testStep(),()=>this.summaryStep()];
      return `<section class="wizard-panel"><div class="wizard-section-title"><span>Krok ${this.step} z 10</span><h2>${esc(ADMIN_STEPS[this.step-1])}</h2></div>${renderers[this.step-1]()}</section>`;
    },

    presetStep() {
      const tiles = Object.entries(this.presets).map(([key,p]) => `<button type="button" class="preset-card ${this.preset===key?"selected":""}" data-preset="${key}"><i class="bi ${p.resource_type==="web"?"bi-globe":"bi-terminal"}"></i><strong>${esc(p.label || key)}</strong><span>${key.includes("full")?"Najwyższe uprawnienia, MFA i krótsza sesja.":key.includes("form")?"Dane z sejfu wstrzykiwane tylko przez worker.":"Bezpieczne wartości możesz zmienić później."}</span></button>`).join("");
      return `<p>Preset ustawia bezpieczne wartości początkowe. Każdą opcję można później zmienić.</p><div class="preset-grid">${tiles}</div>${this.preset==="custom"?`<div class="mt-4"><h3>Wybierz protokół konfiguracji niestandardowej</h3><div class="btn-group"><button class="btn ${this.resourceType==="ssh"?"btn-primary":"btn-outline-primary"}" data-custom-type="ssh">SSH</button><button class="btn ${this.resourceType==="web"?"btn-primary":"btn-outline-primary"}" data-custom-type="web">WWW</button></div></div>`:""}`;
    },

    existingResourceStep() { const servers=this.pam.state().data.servers||[];return `<section class="wizard-panel"><div class="wizard-section-title"><span>Krok 1 z 10</span><h2>Wybierz istniejący zasób</h2></div><div class="resource-choice">${servers.map(s=>`<button data-existing-resource="${s.id}" class="${String(this.field("resource_id"))===String(s.id)?"selected":""}"><i class="bi ${s.protocol==="web"?"bi-globe":"bi-terminal"}"></i><strong>${esc(s.display_name||s.hostname)}</strong><span>${esc((s.protocol||"ssh").toUpperCase())} · ${esc(s.environment)} · ${esc(s.criticality)}</span></button>`).join("")||"Brak zasobów"}</div></section>`; },
    existingOverviewStep() { const s=(this.pam.state().data.servers||[]).find(x=>String(x.id)===String(this.field("resource_id")));return `<section class="wizard-panel"><div class="wizard-section-title"><span>Krok 2 z 10</span><h2>Informacje podstawowe</h2></div><div class="summary-grid"><article><h3>${esc(s?.display_name||s?.hostname)}</h3><dl><dt>Host</dt><dd>${esc(s?.hostname)}</dd><dt>Protokół</dt><dd>${esc((s?.protocol||"ssh").toUpperCase())}</dd><dt>Środowisko</dt><dd>${esc(s?.environment)}</dd><dt>Krytyczność</dt><dd>${esc(s?.criticality)}</dd></dl></article></div></section>`; },

    basicStep() {
      const groups = this.pam.state().data.serverGroups || [];
      return `<div class="form-grid wizard-fields">${this.input("resource.name","Nazwa zasobu","np. Panel administracyjny ERP","Nazwa widoczna użytkownikom.")}${this.input("resource.description","Opis","Do czego służy zasób?","Krótko wyjaśnij cel i zakres.","textarea")}${this.select("resource.environment","Środowisko",[["dev","Development"],["test","Test"],["stage","Stage"],["prod","Produkcja"]])}${this.input("resource.owner","Właściciel","np. Zespół ERP","Osoba lub zespół odpowiedzialny.")}${this.select("resource.criticality","Krytyczność",[["low","Niska"],["medium","Średnia"],["high","Wysoka"],["critical","Krytyczna"]])}${this.input("resource.tags_text","Tagi","erp, finanse, tier-1","Oddziel przecinkami.")}<label class="form-label span-2">Grupa zasobów<select class="form-select" data-bind="resource.resource_group_id"><option value="">Bez grupy</option>${groups.map((g)=>`<option value="${g.id}" ${String(this.field("resource.resource_group_id"))===String(g.id)?"selected":""}>${esc(g.name)}</option>`).join("")}</select><small>Możesz użyć istniejącej grupy albo przygotować nową poniżej.</small></label><details class="span-2"><summary>Utwórz nową grupę zasobów bez opuszczania kreatora</summary>${this.input("resource.new_group_name","Nazwa nowej grupy","np. Systemy finansowe","")}</details><label class="form-check span-2"><input class="form-check-input" type="checkbox" data-bind="resource.enabled" ${this.field("resource.enabled",true)?"checked":""}><span class="form-check-label">Zasób aktywny po utworzeniu</span></label></div>`;
    },

    connectionStep() { return this.resourceType === "web" ? this.webConnection() : this.sshConnection(); },
    sshConnection() {
      return `<div class="form-grid wizard-fields">${this.input("connection.hostname","Hostname lub adres IP","ssh.example.internal","Na tej podstawie zaproponujemy nazwę wyświetlaną.")}${this.input("connection.port","Port","22","Domyślny port SSH.","number")}${this.input("connection.target_username","Konto docelowe","deploy","Konto używane podczas sesji.")}${this.input("connection.administrative_username","Konto administracyjne PAM","pam-admin","Konto do zestawienia kontrolowanego połączenia.")}${this.select("connection.host_key_policy","Polityka klucza hosta",[["strict","Ścisła weryfikacja"],["manual_fingerprint","Ręczny fingerprint"],["trust_on_first_use","Trust on first use"]])}${this.input("connection.expected_host_key_fingerprint","Oczekiwany fingerprint","SHA256:…","Wymagany przy polityce ręcznej.")}${this.input("connection.connection_timeout_seconds","Timeout połączenia (s)","10","Zakres 1–120 sekund.","number")}${this.select("connection.sudo_mode","Polityka sudo",[["none","Brak sudo"],["limited","Ograniczone sudo"],["full","Pełne sudo"]])}<label class="form-check"><input class="form-check-input" type="checkbox" data-bind="connection.gateway_enabled" ${this.field("connection.gateway_enabled",true)?"checked":""}><span>Wymagaj gateway</span></label><label class="form-check"><input class="form-check-input" type="checkbox" data-bind="connection.direct_access_enabled" ${this.field("connection.direct_access_enabled")?"checked":""}><span>Zezwól na dostęp bezpośredni</span></label><details class="span-2"><summary>Konfiguracja zaawansowana SSH</summary>${this.input("connection.command_allowlist","Dozwolone polecenia sudo","systemctl status *, journalctl *","Jedno polecenie na linię.","textarea")}</details></div>`;
    },

    webConnection() {
      const url = this.field("connection.start_url"); const privateWarning = /(^https?:\/\/)?(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i.test(url);
      return `<div class="form-grid wizard-fields">${this.input("connection.start_url","Początkowy URL","https://admin.example.com","HTTP i HTTPS są jedynymi dozwolonymi schematami.")}<div class="field-note ${privateWarning?"warning":""}">${privateWarning?"Adres wygląda na lokalny lub prywatny. Wymaga jawnej zgody polityki.":"Domena zostanie automatycznie dodana do listy dozwolonych."}</div>${this.input("connection.allowed_domains_text","Dozwolone domeny","admin.example.com","Oddziel przecinkami.")}${this.input("connection.blocked_domains_text","Blokowane domeny","metadata.google.internal","Oddziel przecinkami.")}${this.input("connection.login_timeout_seconds","Limit logowania (s)","30","Maksymalny czas oczekiwania na logowanie.","number")}${this.input("connection.idle_timeout_seconds","Limit bezczynności (s)","900","Sesja zostanie automatycznie zakończona.","number")}${this.input("connection.maximum_session_duration_minutes","Maksymalny czas sesji (min)","60","Limit bezwzględny.","number")}${this.select("connection.clipboard_policy","Polityka schowka",[["deny","Zablokowany"],["read","Tylko odczyt"],["write","Tylko zapis"],["read_write","Odczyt i zapis"]])}<label class="form-check"><input class="form-check-input" type="checkbox" data-bind="connection.allow_subdomains" ${this.field("connection.allow_subdomains",true)?"checked":""}><span>Zezwól na subdomeny dozwolonych domen</span></label><label class="form-check"><input class="form-check-input" type="checkbox" data-bind="connection.allow_downloads" ${this.field("connection.allow_downloads")?"checked":""}><span>Zezwól na pobieranie</span></label><label class="form-check"><input class="form-check-input" type="checkbox" data-bind="connection.allow_uploads" ${this.field("connection.allow_uploads")?"checked":""}><span>Zezwól na wysyłanie</span></label><label class="form-check span-2"><input class="form-check-input" type="checkbox" data-bind="connection.allow_private_network" ${this.field("connection.allow_private_network")?"checked":""}><span>Jawnie zezwól na prywatną sieć docelową</span></label><button type="button" class="btn btn-outline-primary span-2" data-wizard="discover"><i class="bi bi-browser-chrome"></i> Otwórz testową przeglądarkę</button>${this.discoveryHtml()}</div>`;
    },

    authStep() {
      if (this.mode !== "create_resource") return `<div class="alert alert-info">Poświadczenia istniejącego zasobu nie są zmieniane w tym scenariuszu.</div>`;
      if (this.resourceType === "ssh") return `<div class="form-grid wizard-fields">${this.select("connection.authentication_type","Metoda uwierzytelniania",[["private_key","Klucz prywatny"],["password","Hasło"],["agent","Agent SSH"]])}${this.secretPicker("connection.secret_ref_id","connection.secret_input_key","ssh_auth","Sekret SSH")}</div>`;
      const auth = this.field("connection.authentication_type","none");
      return `<div class="form-grid wizard-fields">${this.select("connection.authentication_type","Sposób logowania",[["none","Brak logowania"],["form","Automatyczny formularz"],["manual","Ręczne logowanie użytkownika"],["basic_auth","Basic Auth"],["http_header","Nagłówek HTTP"],["cookie","Cookie"]])}${auth==="form"||auth==="basic_auth"?`${this.secretPicker("connection.username_secret_id","connection.username_secret_input_key","web_user","Login")}${this.secretPicker("connection.password_secret_id","connection.password_secret_input_key","web_password","Hasło")}${auth==="form"?this.selectorConfig():""}`:auth==="none"||auth==="manual"?"":`${this.secretPicker("connection.auth_secret_id","connection.auth_secret_input_key","web_auth","Sekret uwierzytelnienia")}${auth==="http_header"?this.input("connection.header_name","Nazwa nagłówka","Authorization","Wartość pochodzi z sejfu."):auth==="cookie"?this.input("connection.cookie_name","Nazwa cookie","session","Wartość pochodzi z sejfu."):""}`}</div>`;
    },

    selectorConfig() {
      return `<div class="span-2 selector-config"><h3>Wskaż pola na stronie</h3><p>Otwórz kontrolowaną przeglądarkę, a następnie wybierz kolejno elementy. Selektory są generowane z id, name, data-*, roli/nazwy dostępności lub selektora względnego.</p><div class="btn-group"><button type="button" class="btn btn-outline-primary" data-picker="username">1. Pole loginu</button><button type="button" class="btn btn-outline-primary" data-picker="password">2. Pole hasła</button><button type="button" class="btn btn-outline-primary" data-picker="submit">3. Przycisk logowania</button><button type="button" class="btn btn-outline-primary" data-picker="success">4. Element sukcesu</button></div><button type="button" class="btn btn-primary mt-2" data-wizard="discover">Wskaż pola na stronie</button>${this.discoveryHtml()}<details><summary>Selektory zaawansowane</summary>${this.input("connection.username_selector","Selektor loginu","#username","")}${this.input("connection.password_selector","Selektor hasła","input[name=password]","")}${this.input("connection.submit_selector","Selektor przycisku","button[type=submit]","")}${this.input("connection.success_dom_selector","Element potwierdzający","[data-testid=dashboard]","")}${this.input("connection.success_url_pattern","Wzorzec końcowego URL","**/dashboard","")}</details></div>`;
    },

    discoveryHtml() {
      if (!this.discovery) return "";
      return `<div class="browser-picker span-2"><div class="picker-toolbar"><strong>Kontrolowana przeglądarka</strong><span>Wybierasz: ${esc(this.pickerRole)}</span></div><div class="picker-stage"><img src="data:${this.discovery.mime_type};base64,${this.discovery.screenshot}" alt="Zrzut kontrolowanej przeglądarki">${this.discovery.candidates.map((c)=>`<button type="button" class="picker-target" data-selector="${esc(c.selector)}" data-suggested="${esc(c.suggested)}" title="${esc(c.accessible_name || c.selector)}" style="left:${c.rect.x/14.4}%;top:${c.rect.y/9}%;width:${Math.max(c.rect.width/14.4,1)}%;height:${Math.max(c.rect.height/9,1)}%"></button>`).join("")}</div><small>Selektory: ${esc(this.discovery.selector_priority.join(" → "))}</small></div>`;
    },

    permissionsStep() {
      const groups = this.pam.state().data.serverGroups || [];
      return `<div class="form-grid wizard-fields"><label class="form-label span-2">Użyj istniejącego profilu dostępu<select class="form-select" data-bind="access_group_id"><option value="">Utwórz nowy profil</option>${groups.map((g)=>`<option value="${g.id}" ${String(this.field("access_group_id"))===String(g.id)?"selected":""}>${esc(g.name)}</option>`).join("")}</select><small>Profil określa dozwolony typ dostępu i limity.</small></label>${!this.field("access_group_id")?`${this.input("access_profile.name","Nazwa profilu","Operatorzy ERP — standard","Czytelna nazwa przeznaczenia dostępu.")}${this.input("access_profile.description","Opis profilu","Dostęp operacyjny bez pełnego sudo","", "textarea")}${this.select("access_profile.access_option","Poziom uprawnień",[["ssh_only","Zwykły dostęp"],["limited_sudo","Ograniczone sudo"],["full_sudo","Pełne sudo"]])}`:""}</div>`;
    },

    securityStep() {
      const critical = ["high","critical"].includes(this.field("resource.criticality"));
      return `<div class="security-cards"><label><input type="checkbox" data-bind="policy.require_recording" ${this.field("policy.require_recording",true)?"checked":""}><strong>Nagrywanie sesji</strong><span>${critical?"Zalecane obowiązkowo dla tej krytyczności.":"Wideo/terminal i zdarzenia."}</span></label><label><input type="checkbox" data-bind="policy.require_command_logging" ${this.field("policy.require_command_logging",true)?"checked":""}><strong>Rejestr zdarzeń/poleceń</strong><span>Bez zapisywania wartości pól wrażliwych.</span></label><label><input type="checkbox" data-bind="policy.require_mfa" ${this.field("policy.require_mfa",critical)?"checked":""}><strong>MFA</strong><span>Wymagaj dodatkowego składnika.</span></label><label><input type="checkbox" data-bind="policy.require_approval" ${this.field("policy.require_approval",true)?"checked":""}><strong>Akceptacja</strong><span>Wymagaj decyzji zatwierdzającego.</span></label></div>${critical&&!this.field("policy.require_recording",true)?this.input("policy.control_override_justification","Uzasadnienie wyjątku","Dlaczego nagrywanie jest wyłączone?","Wymagane i audytowane.","textarea"):""}`;
    },

    assignmentsStep() {
      return `<div class="span-2">
            <h6>Kto będzie miał dostęp?</h6>
            <div class="text-muted small mb-3">Wyszukaj i wybierz użytkowników lub grupy, którzy od razu otrzymają dostęp.</div>
            <input type="text" class="form-control mb-3" placeholder="Wpisz nazwę..." list="wizard-users-list" data-wizard-search="user">
            <datalist id="wizard-users-list">
              ${(this.pam.state().data.users||[]).map(u=>`<option value="${u.id}">${u.username} ${u.first_name?`(${u.first_name} ${u.last_name})`:""}</option>`).join("")}
              ${(this.pam.state().data.groups||[]).map(g=>`<option value="g${g.id}">${g.name} (Grupa)</option>`).join("")}
            </datalist>
            <div class="d-flex flex-wrap gap-2">
              ${(this.data.assignments||[]).map(a=>{
                let name = a.subject_identifier;
                if (a.subject_type === 'user') {
                  const u = (this.pam.state().data.users||[]).find(x=>String(x.id)===String(a.subject_identifier));
                  if (u) name = u.username;
                } else if (a.subject_type === 'group') {
                  const g = (this.pam.state().data.groups||[]).find(x=>String(x.id)===String(a.subject_identifier));
                  if (g) name = g.name + " (Grupa)";
                }
                return `<div class="badge bg-primary p-2 d-flex align-items-center">${name} <i class="bi bi-x-circle ms-2 cursor-pointer" data-remove-assignment="${a.subject_type}:${a.subject_identifier}"></i></div>`;
              }).join("")}
            </div>
          </div>`;
    },

    approvalStep() {
      return `<div class="form-grid wizard-fields">${this.input("policy.maximum_duration_minutes","Maksymalny czas (min)","60","Górna granica wniosku.","number")}${this.input("policy.allowed_durations_text","Dostępne czasy","30,60","Minuty oddzielone przecinkami.")}${this.input("policy.allowed_hours","Dozwolone godziny UTC","8-18","Pozostaw puste dla całej doby.")}${this.input("policy.allowed_weekdays","Dni tygodnia","0,1,2,3,4,5,6","0 = poniedziałek.")}<label class="form-check span-2"><input class="form-check-input" type="checkbox" data-bind="policy.require_approval" ${this.field("policy.require_approval",true)?"checked":""}><span>Wymagaj akceptacji przed utworzeniem grantu</span></label></div>`;
    },

    testStep() {
      return `<p>Test wykonywany jest przez backendowy worker. Każdy etap zwraca osobny, bezpiecznie zredagowany wynik.</p><button class="btn btn-primary btn-lg" type="button" data-wizard="test"><i class="bi bi-plug"></i> ${this.resourceType==="web"?"Otwórz testową przeglądarkę i sprawdź":"Sprawdź połączenie"}</button>${this.checksHtml()}`;
    },
    checksHtml() { return this.checks.length ? `<div class="check-list">${this.checks.map((c)=>`<article class="check-${c.status}"><i class="bi ${c.status==="success"?"bi-check-circle":c.status==="error"?"bi-x-circle":"bi-dash-circle"}"></i><div><strong>${esc(c.name)}</strong><span>${esc(c.message)}</span>${c.technical_detail?`<details><summary>Szczegóły techniczne</summary><code>${esc(c.technical_detail)}</code></details>`:""}</div></article>`).join("")}</div>` : ""; },

    summaryStep() {
      const r=this.data.resource||{},c=this.data.connection||{},p=this.data.policy||{};
      return `<div class="summary-grid"><article><h3>Zasób</h3><dl><dt>Nazwa</dt><dd>${esc(r.name)}</dd><dt>Typ</dt><dd>${esc(this.resourceType?.toUpperCase())}</dd><dt>Środowisko</dt><dd>${esc(r.environment)}</dd><dt>Krytyczność</dt><dd>${esc(r.criticality)}</dd></dl></article><article><h3>Połączenie</h3><dl><dt>Cel</dt><dd>${esc(this.resourceType==="web"?c.start_url:`${c.hostname}:${c.port||22}`)}</dd><dt>Logowanie</dt><dd>${esc(c.authentication_type)}</dd><dt>Gateway</dt><dd>${c.gateway_enabled?"tak":"nie"}</dd></dl></article><article><h3>Kontrole</h3><dl><dt>MFA</dt><dd>${p.require_mfa?"tak":"nie"}</dd><dt>Akceptacja</dt><dd>${p.require_approval?"tak":"nie"}</dd><dt>Nagrywanie</dt><dd>${p.require_recording?"tak":"nie"}</dd><dt>Limit</dt><dd>${esc(p.maximum_duration_minutes)} min</dd></dl></article><article><h3>Przydziały</h3><p>${(this.data.assignments||[]).length} reguł przydziału</p><p class="text-secondary">Tworzenie jest atomowe. Błąd cofnie zasób, sekret, profil i członkostwa.</p></article></div>`;
    },

    requestContent() {
      const servers=this.pam.state().data.servers||[], groups=this.pam.state().data.serverGroups||[]; const server=servers.find(s=>String(s.id)===String(this.field("resource_id"))); const allowed=new Set(server?.access_group_ids||[]);
      if(this.step===1)return `<section class="wizard-panel"><h2>Wybierz zasób</h2><div class="resource-choice">${servers.map(s=>`<button data-request-resource="${s.id}" class="${String(this.field("resource_id"))===String(s.id)?"selected":""}"><i class="bi ${s.protocol==="web"?"bi-globe":"bi-terminal"}"></i><strong>${esc(s.display_name||s.hostname)}</strong><span>${esc(s.environment)} · ${esc(s.criticality)}</span></button>`).join("")||"Brak dostępnych zasobów"}</div></section>`;
      if(this.step===2)return `<section class="wizard-panel"><h2>Wybierz profil dostępu</h2><div class="resource-choice">${groups.filter(g=>allowed.has(g.id)).map(g=>`<button data-request-profile="${g.id}" class="${String(this.field("access_group_id"))===String(g.id)?"selected":""}"><strong>${esc(g.name)}</strong><span>maks. ${g.max_grant_minutes} min · ${g.require_approval?"wymaga akceptacji":"auto"}</span></button>`).join("")||"Ten zasób nie ma dostępnego profilu"}</div></section>`;
      if(this.step===3)return `<section class="wizard-panel"><h2>Wybierz czas dostępu</h2><div class="duration-grid">${[30,60,120,240,480].map(v=>`<button data-duration="${v}" class="${Number(this.field("duration_minutes"))===v?"selected":""}">${v<60?v+" min":v/60+" h"}</button>`).join("")}</div></section>`;
      return `<section class="wizard-panel"><h2>Uzasadnij dostęp</h2>${this.input("justification","Uzasadnienie","Opisz zadanie, ticket i oczekiwany rezultat","Minimum 10 znaków.","textarea")}<div class="alert alert-info mt-3">Wniosek dotyczy zasobu <strong>${esc(server?.display_name||server?.hostname)}</strong> na ${esc(this.field("duration_minutes"))} minut.</div></section>`;
    },

    input(path,label,placeholder,help,type="text") { const raw=path.endsWith("_text")?(this.field(path.slice(0,-5),[])||[]).join(", "):this.field(path);const value=esc(raw); return `<label class="form-label ${type==="textarea"?"span-2":""}">${esc(label)}${type==="textarea"?`<textarea class="form-control" data-bind="${path}" placeholder="${esc(placeholder)}">${value}</textarea>`:`<input class="form-control" type="${type}" data-bind="${path}" value="${value}" placeholder="${esc(placeholder)}">`}<small>${esc(help)}</small><span class="invalid-feedback"></span></label>`; },
    select(path,label,options) { const current=String(this.field(path)); return `<label class="form-label">${esc(label)}<select class="form-select" data-bind="${path}">${options.map(([v,n])=>`<option value="${esc(v)}" ${current===String(v)?"selected":""}>${esc(n)}</option>`).join("")}</select></label>`; },
    secretPicker(refPath,keyPath,key,label) { const secrets=this.pam.state().data.secrets||[]; const selected=String(this.field(refPath));this.set(keyPath,selected?null:key); return `<div class="secret-picker"><label>${esc(label)}<select class="form-select" data-bind="${refPath}"><option value="">Utwórz nowy sekret</option>${secrets.map(s=>`<option value="${s.id}" ${selected===String(s.id)?"selected":""}>${esc(s.name)} (${esc(s.secret_type)})</option>`).join("")}</select></label>${!selected?`<input class="form-control mt-2" data-secret-name="${key}" value="${esc(this.secretInputs[key]?.name||"")}" placeholder="Nazwa sekretu"><input class="form-control mt-2" type="password" data-secret-value="${key}" value="${esc(this.secretInputs[key]?.value||"")}" placeholder="Wartość — nie będzie zapisana w drafcie"><small>Wartość pozostaje tylko w pamięci tej strony do testu/utworzenia.</small>`:""}</div>`; },
    footer() { return `<footer class="wizard-footer"><button class="btn btn-outline-secondary" data-wizard="back" ${this.step===1?"disabled":""}><i class="bi bi-arrow-left"></i> Wstecz</button><span>Krok ${this.step} / ${this.steps.length}</span><button class="btn btn-primary" data-wizard="${this.step===this.steps.length?"complete":"next"}">${this.step===this.steps.length?(this.mode==="request_access"?"Wyślij wniosek":"Utwórz dostęp"):"Dalej"} <i class="bi bi-arrow-right"></i></button></footer>`; },

    bind() {
      this.root.querySelectorAll("[data-mode]").forEach(el=>el.onclick=()=>this.chooseMode(el.dataset.mode));
      this.root.querySelectorAll("[data-preset]").forEach(el=>el.onclick=()=>this.choosePreset(el.dataset.preset));
      this.root.querySelectorAll("[data-custom-type]").forEach(el=>el.onclick=()=>{this.resourceType=el.dataset.customType;this.scheduleSave();this.render()});
      this.root.querySelectorAll("[data-jump]").forEach(el=>el.onclick=()=>{this.step=Number(el.dataset.jump);this.render()});
      this.root.querySelectorAll("[data-bind]").forEach(el=>{
        const update=()=>{let value=el.type==="checkbox"?el.checked:el.type==="number"?Number(el.value):el.value;if(el.dataset.bind.endsWith("_text")){const path=el.dataset.bind.slice(0,-5);this.set(path,el.value.split(",").map(v=>v.trim()).filter(Boolean));}else this.set(el.dataset.bind,value);if(el.dataset.bind==="connection.start_url")this.deriveDomain(value);if(el.dataset.bind==="connection.hostname"&&!this.field("resource.name"))this.set("resource.name",value.split(".")[0]);if(el.dataset.bind==="resource.criticality"&&["high","critical"].includes(value))this.set("policy.require_recording",true);if(el.dataset.bind==="assignment_role"){this.data.assignments=(this.data.assignments||[]).filter(a=>a.subject_type!=="role");if(value)this.data.assignments.push({subject_type:"role",subject_identifier:value,assignment_mode:this.field("assignment_mode","request_required")})}if(el.dataset.bind==="assignment_mode")this.data.assignments=(this.data.assignments||[]).map(a=>({...a,assignment_mode:value}));this.validateField(el);this.scheduleSave();if(el.dataset.bind==="connection.authentication_type"||el.dataset.bind.endsWith("_secret_id"))this.render()}; el.oninput=update;el.onchange=update;
      });
      this.root.querySelectorAll("[data-secret-name]").forEach(el=>el.oninput=()=>{const k=el.dataset.secretName;this.secretInputs[k]={...(this.secretInputs[k]||{}),name:el.value,secret_type:k.includes("key")?"ssh_private_key":"password",value:this.secretInputs[k]?.value||""}});
      this.root.querySelectorAll("[data-secret-value]").forEach(el=>el.oninput=()=>{const k=el.dataset.secretValue;this.secretInputs[k]={...(this.secretInputs[k]||{}),name:this.secretInputs[k]?.name||k,secret_type:k.includes("key")?"ssh_private_key":"password",value:el.value}});
      this.root.querySelectorAll("[data-assignment-user]").forEach(el=>el.onchange=()=>{const id=String(el.dataset.assignmentUser);this.data.assignments=(this.data.assignments||[]).filter(a=>!(a.subject_type==="user"&&String(a.subject_identifier)===id));if(el.checked)this.data.assignments.push({subject_type:"user",subject_identifier:id,assignment_mode:this.field("assignment_mode","request_required")});this.scheduleSave()});
      this.root.querySelectorAll("[data-wizard-search]").forEach(el=>el.onchange=(e)=>{
        const val = e.target.value;
        if(!val)return;
        let type = "user", id = val;
        if(val.startsWith("g")){ type="group"; id=val.slice(1); }
        this.data.assignments=(this.data.assignments||[]).filter(a=>!(a.subject_type===type&&String(a.subject_identifier)===id));
        this.data.assignments.push({subject_type:type,subject_identifier:id,assignment_mode:this.field("assignment_mode","request_required")});
        e.target.value = "";
        this.scheduleSave();
        this.render();
      });
      this.root.querySelectorAll("[data-remove-assignment]").forEach(el=>el.onclick=()=>{
        const [type, id] = el.dataset.removeAssignment.split(":");
        this.data.assignments=(this.data.assignments||[]).filter(a=>!(a.subject_type===type&&String(a.subject_identifier)===id));
        this.scheduleSave();
        this.render();
      });
      this.root.querySelectorAll("[data-picker]").forEach(el=>el.onclick=()=>{this.pickerRole=el.dataset.picker;this.render()});
      this.root.querySelectorAll("[data-selector]").forEach(el=>el.onclick=()=>{const role=this.pickerRole||el.dataset.suggested;const map={username:"username_selector",password:"password_selector",submit:"submit_selector",success:"success_dom_selector"};this.set(`connection.${map[role]}`,el.dataset.selector);this.pickerRole=role==="username"?"password":role==="password"?"submit":role==="submit"?"success":"success";this.scheduleSave();this.render()});
      this.root.querySelectorAll("[data-request-resource]").forEach(el=>el.onclick=()=>{this.set("resource_id",Number(el.dataset.requestResource));this.set("access_group_id",null);this.scheduleSave();this.render()});
      this.root.querySelectorAll("[data-existing-resource]").forEach(el=>el.onclick=()=>{const server=(this.pam.state().data.servers||[]).find(s=>String(s.id)===String(el.dataset.existingResource));this.set("resource_id",Number(el.dataset.existingResource));this.resourceType=server?.protocol||"ssh";this.set("resource",{name:server?.display_name||server?.hostname,environment:server?.environment,criticality:server?.criticality});this.set("access_group_id",null);this.scheduleSave();this.render()});
      this.root.querySelectorAll("[data-request-profile]").forEach(el=>el.onclick=()=>{this.set("access_group_id",Number(el.dataset.requestProfile));this.scheduleSave();this.render()});
      this.root.querySelectorAll("[data-duration]").forEach(el=>el.onclick=()=>{this.set("duration_minutes",Number(el.dataset.duration));this.scheduleSave();this.render()});
      this.root.querySelectorAll("[data-wizard]").forEach(el=>el.onclick=()=>this.action(el.dataset.wizard));
    },

    deriveDomain(value) { try { const url=new URL(value.includes("://")?value:`https://${value}`);if(!this.field("connection.allowed_domains")?.length){this.set("connection.allowed_domains",[url.hostname]);this.set("connection.allowed_domains_text",url.hostname)}if(!this.field("resource.name"))this.set("resource.name",url.hostname.split(".")[0])}catch(_){} },
    validateField(el) { let message="";const path=el.dataset.bind,value=el.value;if(path==="connection.start_url"){try{const parsed=new URL(value.includes("://")?value:`https://${value}`);if(!["http:","https:"].includes(parsed.protocol))message="Dozwolone są tylko HTTP i HTTPS"}catch(_){message="Podaj poprawny adres URL"}}if(path==="connection.port"&&(!Number.isInteger(Number(value))||Number(value)<1||Number(value)>65535))message="Port musi mieścić się w zakresie 1–65535";if(["resource.name","connection.hostname","connection.target_username"].includes(path)&&!String(value).trim())message="To pole jest wymagane";el.classList.toggle("is-invalid",!!message);const feedback=el.parentElement?.querySelector(".invalid-feedback");if(feedback)feedback.textContent=message;return !message; },
    transientSecrets() { const result={};for(const [key,item] of Object.entries(this.secretInputs))if(item.value)result[key]={name:item.name||key,secret_type:item.secret_type||"password",value:item.value};return result; },

    async action(name) {
      try {
        if(name==="close"){this.close();return} if(name==="back"){this.step--;this.render();return}
        if(name==="discover"){await this.discover();return} if(name==="test"){await this.testConnection();return}
        if(name==="next"){
          if(this.mode==="create_resource"&&this.step===1&&!this.resourceType){this.showError("Wybierz preset lub konfigurację niestandardową");return}
          if(this.mode==="assign_existing_resource"&&this.step===1&&!this.field("resource_id")){this.showError("Wybierz istniejący zasób");return}
          if(this.mode==="request_access"){const required=["resource_id","access_group_id","duration_minutes","justification"][this.step-1];if(!this.field(required)){this.showError("Uzupełnij wymagane dane");return}}
          await this.save(); const validation=await this.pam.api("/api/access-wizard/validate-step",{method:"POST",body:JSON.stringify({mode:this.mode,resource_type:this.resourceType,step:this.mode==="request_access"?(this.step===4?8:this.step+1):this.step,data:this.data})});if(!validation.valid){this.showError("Popraw dane przed przejściem dalej",validation.errors);return}this.step++;this.render();return;
        }
        if(name==="complete")await this.complete();
      } catch(error){this.showError(error.message || "Operacja nie powiodła się",error.detail?.errors||error.detail?.detail?.errors||[])}
    },

    async discover() {
      const url=this.field("connection.start_url");if(!url){this.showError("Najpierw podaj początkowy URL");return}
      this.discovery=await this.pam.api("/api/access-wizard/discover-web-login",{method:"POST",body:JSON.stringify({start_url:url,allowed_domains:this.field("connection.allowed_domains",[]),blocked_domains:this.field("connection.blocked_domains",[]),allow_private_network:!!this.field("connection.allow_private_network"),allow_subdomains:this.field("connection.allow_subdomains",true)})});this.render();
    },

    async testConnection() {
      this.checks=[];this.render();
      const result=await this.pam.api("/api/access-wizard/test-connection",{method:"POST",body:JSON.stringify({resource_type:this.resourceType,resource:this.data.resource||{},connection:this.data.connection||{},secret_inputs:this.transientSecrets()})});
      this.checks=result.checks;this.set("connection_test",{passed:!result.blocking,tested_at:new Date().toISOString(),checks:result.checks.map(c=>({name:c.name,status:c.status}))});await this.save();this.render();
    },

    async complete() {
      if(this.mode==="request_access"&&String(this.field("justification","")).trim().length<10){this.showError("Uzasadnienie musi mieć co najmniej 10 znaków");return}
      await this.save(); const result=await this.pam.api("/api/access-wizard/complete",{method:"POST",body:JSON.stringify({draft_id:this.draftId,submission_key:crypto.randomUUID(),secret_inputs:this.transientSecrets(),accept_warnings:false})});
      this.secretInputs={};this.root.querySelector(".wizard-main").innerHTML=`<div class="wizard-success"><i class="bi bi-check-circle"></i><h2>${this.mode==="request_access"?"Wniosek został wysłany":"Dostęp został utworzony"}</h2><p>Identyfikator: ${esc(result.request_id||result.server_id)}</p><button class="btn btn-primary" data-wizard="finish">Wróć do PAM</button></div>`;this.root.querySelector("[data-wizard=finish]").onclick=async()=>{this.close();await this.pam.refresh()};
    }
  };

  window.AccessWizard = wizard;
})();
