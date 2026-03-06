"""Unit tests for the reconstructor (code generation)."""
import pytest
from pathlib import Path
from app.models.artifact import FunctionArtifact, GlobalArtifact
from app.pipeline.type_refiner import TypeRefiner
from app.pipeline.module_classifier import ModuleClassifier
from app.pipeline.reconstructor import Reconstructor


def _make_art(addr: int, name: str, decompiled: str = "", is_exported: bool = False) -> FunctionArtifact:
    art = FunctionArtifact(
        address=addr, name=name,
        decompiled_code=decompiled or None,
        decompile_ok=bool(decompiled),
        is_exported=is_exported,
    )
    return art


def test_type_refiner_scores_decompile():
    art = _make_art(0x1000, "sub_1000", decompiled="int sub_1000() { return 0; }")
    globals_ = GlobalArtifact()
    TypeRefiner().run([art], globals_)
    assert art.confidence_score >= 30


def test_type_refiner_annotates_low():
    art = _make_art(0x1000, "sub_1000", decompiled="int sub_1000() {}")
    globals_ = GlobalArtifact()
    TypeRefiner().run([art], globals_)
    assert "TODO: inferred" in (art.decompiled_code or "")


def test_module_classifier_by_prefix():
    art = _make_art(0x2000, "net_connect", is_exported=True)
    globals_ = GlobalArtifact(exports=[{"name": "net_connect", "address": 0x2000}])
    modules = ModuleClassifier().run([art], globals_)
    assert "net" in modules or art.module is not None


def test_reconstructor_builds_project(tmp_path):
    art = _make_art(0x3000, "crypto_hash", decompiled="void crypto_hash() {}")
    art.module = "crypto"
    globals_ = GlobalArtifact()
    modules = {"crypto": [art]}

    reconstructor = Reconstructor()
    project = reconstructor.build(
        job_id="test01",
        dll_name="test",
        output_dir=tmp_path,
        modules=modules,
        globals_=globals_,
        all_artifacts=[art],
    )
    assert project.header_file is not None
    assert len(project.source_files) == 1
    assert "crypto_hash" in project.source_files[0].content


def test_reconstructor_write_to_disk(tmp_path):
    art = _make_art(0x4000, "io_read", decompiled="int io_read() { return 1; }")
    art.module = "io"
    globals_ = GlobalArtifact()
    modules = {"io": [art]}

    project = Reconstructor().build("job02", "mylib", tmp_path, modules, globals_, [art])
    project.write_to_disk()

    out = tmp_path / "job02"
    assert (out / "include" / "recovered_types.h").exists()
    assert (out / "src" / "io.cpp").exists()
    assert (out / "CMakeLists.txt").exists()
    assert (out / "README_recovered.md").exists()


def test_module_classifier_prefers_source_path_hints():
    art = _make_art(
        0x5000,
        "sub_5000",
        decompiled='int sub_5000() { log_error("C:/work/game/src/net/http/client.cpp"); return 0; }',
    )

    modules = ModuleClassifier().run([art], GlobalArtifact())

    assert "net/http/client" in modules
    assert art.module_reason == "source_path"
    assert art.guessed_name is not None


def test_reconstructor_supports_nested_module_paths(tmp_path):
    art = _make_art(0x6000, "sub_6000", decompiled="void sub_6000() {}")
    art.module = "net/http/client"
    art.module_reason = "source_path"
    art.source_candidates = ["src/net/http/client.cpp"]
    modules = {"net/http/client": [art]}

    project = Reconstructor().build("job03", "mylib", tmp_path, modules, GlobalArtifact(), [art])
    project.write_to_disk()

    out = tmp_path / "job03"
    assert (out / "src" / "net" / "http" / "client.cpp").exists()


def test_reconstructor_emits_buildable_stubs_and_exports(tmp_path):
    art = _make_art(0x6100, "InitPlugin", decompiled="int InitPlugin() { return 1; }")
    art.module = "runtime/msvc_crt"
    art.module_reason = "symbol_prefix"
    globals_ = GlobalArtifact(exports=[{"name": "InitPlugin", "address": 0x6100, "ordinal": 1}])
    modules = {"runtime/msvc_crt": [art]}

    project = Reconstructor().build("job04", "sample", tmp_path, modules, globals_, [art])
    project.write_to_disk()

    out = tmp_path / "job04"
    source = (out / "src" / "runtime" / "msvc_crt.cpp").read_text(encoding="utf-8")
    header = (out / "include" / "recovered_types.h").read_text(encoding="utf-8")
    cmake = (out / "CMakeLists.txt").read_text(encoding="utf-8")
    exports = (out / "exports.def").read_text(encoding="utf-8")
    proxy_cmake = (out / "proxy" / "CMakeLists.txt").read_text(encoding="utf-8")
    proxy_exports = (out / "proxy" / "proxy_exports.def").read_text(encoding="utf-8")

    assert 'extern "C" recovered_word_t fn_6100()' in source
    assert "// int InitPlugin() { return 1; }" in source
    assert "recovered_word_t fn_6100();" in header
    assert "add_library(${PROJECT_NAME} SHARED" in cmake
    assert "InitPlugin=fn_6100 @1" in exports
    assert "add_library(${PROJECT_NAME} SHARED proxy.cpp)" in proxy_cmake
    assert "InitPlugin=sample_original.InitPlugin @1" in proxy_exports


def test_module_classifier_collapses_runtime_symbols():
    art = _make_art(0x7000, "__scrt_initialize_thread_safe_statics")

    modules = ModuleClassifier().run([art], GlobalArtifact())

    assert "runtime/msvc_crt" in modules
    assert art.module_reason == "symbol_prefix"


def test_module_classifier_does_not_split_random_underscore_names():
    art = _make_art(0x7100, "unknown_libname")

    modules = ModuleClassifier().run([art], GlobalArtifact())

    assert "unknown_libname" not in modules
    assert art.module == "misc"


def test_module_classifier_maps_demangled_std_destructor_to_runtime_stl():
    art = _make_art(0x7200, "sub_7200")
    art.demangled_name = "int `std::num_put<char,std::ostreambuf_iterator<char>>::do_put(...)'::`1'::dtor$0"

    modules = ModuleClassifier().run([art], GlobalArtifact())

    assert "runtime/stl" in modules
    assert art.module == "runtime/stl"


def test_module_classifier_maps_localeupdate_class_to_runtime_stl():
    art = _make_art(0x7300, "sub_7300")
    art.demangled_name = "_LocaleUpdate::GetLocaleT(void)"

    modules = ModuleClassifier().run([art], GlobalArtifact())

    assert "runtime/stl" in modules
    assert art.module == "runtime/stl"


def test_module_classifier_maps_unknown_libname_to_runtime_crt():
    art = _make_art(0x7400, "unknown_libname_58")

    modules = ModuleClassifier().run([art], GlobalArtifact())

    assert "runtime/msvc_crt" in modules
    assert art.module == "runtime/msvc_crt"


def test_module_classifier_does_not_propagate_runtime_into_large_component():
    seed = _make_art(0x8000, "__scrt_initialize_thread_safe_statics")
    seed.module = "runtime/msvc_crt"
    seed.module_reason = "symbol_prefix"
    seed.callees = [0x8001]

    others = []
    for offset in range(1, 66):
        art = _make_art(0x8000 + offset, f"sub_{0x8000 + offset:X}")
        if offset < 65:
            art.callees = [0x8000 + offset + 1]
        others.append(art)

    modules = ModuleClassifier().run([seed, *others], GlobalArtifact())

    assert "runtime/msvc_crt" in modules
    assert any(art.module == "misc" for art in others)


def test_module_classifier_propagates_small_non_runtime_component():
    seed = _make_art(0x9000, "net_connect", is_exported=True)
    seed.module = "net"
    seed.module_reason = "export_prefix"
    seed.callees = [0x9001]

    b = _make_art(0x9001, "sub_9001")
    b.callees = [0x9002]
    c = _make_art(0x9002, "sub_9002")

    modules = ModuleClassifier().run([seed, b, c], GlobalArtifact(exports=[{"name": "net_connect", "address": 0x9000}]))

    assert "net" in modules
    assert b.module == "net"
    assert c.module == "net"


def test_module_classifier_detects_bulk_string_initializers():
    art = _make_art(
        0xA000,
        "sub_A000",
        decompiled=(
            'int sub_A000() { qword_1 = (__int64)"Wood"; qword_2 = (__int64)"Stone"; '
            'qword_3 = (__int64)"Iron"; qword_4 = (__int64)"Coal"; qword_5 = (__int64)"Gold"; '
            'qword_6 = (__int64)"Fiber"; qword_7 = (__int64)"Bone"; qword_8 = (__int64)"Leather"; '
            'qword_9 = (__int64)"Oil"; qword_10 = (__int64)"Cake"; qword_11 = (__int64)"PalSphere"; '
            'qword_12 = (__int64)"Venom"; return atexit(sub_B000); }'
        ),
    )

    modules = ModuleClassifier().run([art], GlobalArtifact())

    assert "data/init_tables" in modules
    assert art.module == "data/init_tables"


def test_module_classifier_detects_cfltcvt_like_string_tables():
    art = _make_art(
        0xA100,
        "_cfltcvt_init",
        decompiled=(
            'const char *f(){ qword_1 = (__int64)"Accessory_AT_1|Attack Pendant"; '
            'qword_2 = (__int64)"Accessory_AT_2|Attack Pendant+1"; '
            'qword_3 = (__int64)"Accessory_AT_3|Attack Pendant+2"; '
            'qword_4 = (__int64)"Accessory_HP_1|Life Pendant"; '
            'qword_5 = (__int64)"Accessory_HP_2|Life Pendant+1"; '
            'qword_6 = (__int64)"Accessory_HP_3|Life Pendant+2"; '
            'qword_7 = (__int64)"Accessory_WorkSpeed_1|Pendant"; '
            'qword_8 = (__int64)"Accessory_WorkSpeed_2|Pendant+1"; return 0; }'
        ),
    )

    modules = ModuleClassifier().run([art], GlobalArtifact())

    assert "data/init_tables" in modules
    assert art.module == "data/init_tables"


def test_module_classifier_detects_pipe_catalog_tables():
    art = _make_art(
        0xA200,
        "sub_A200",
        decompiled=(
            'void f(){ use("PalSphere|Pal Sphere"); use("PalSphere_Mega|Mega Sphere"); '
            'use("PalSphere_Giga|Giga Sphere"); use("PalSphere_Tera|Hyper Sphere"); }'
        ),
    )

    modules = ModuleClassifier().run([art], GlobalArtifact())

    assert "data/catalog" in modules
    assert art.module == "data/catalog"


def test_module_classifier_detects_imgui_and_debug_strings():
    art = _make_art(
        0xA300,
        "sub_A300",
        decompiled='void f(){ use("imgui_impl_dx11"); use("xinput1_4.dll"); }',
    )
    dbg = _make_art(
        0xA301,
        "sub_A301",
        decompiled='void g(){ use("##Tooltip_%02d"); use("RefScale=%f"); }',
    )

    modules = ModuleClassifier().run([art, dbg], GlobalArtifact())

    assert "third_party/imgui" in modules
    assert "ui/debug" in modules
    assert art.module == "third_party/imgui"
    assert dbg.module == "ui/debug"


def test_module_classifier_detects_fmt_format_strings():
    art = _make_art(
        0xA400,
        "sub_A400",
        decompiled='void f(){ use("Invalid format string."); use("Argument not found."); }',
    )

    modules = ModuleClassifier().run([art], GlobalArtifact())

    assert "third_party/fmt" in modules
    assert art.module == "third_party/fmt"


def test_module_classifier_detects_gameplay_string_signatures():
    weapon = _make_art(
        0xA500,
        "sub_A500",
        decompiled='void f(){ use("PalShooterComponent"); use("PalWeaponBase"); use("GetRemainBulletCount"); }',
    )
    character = _make_art(
        0xA501,
        "sub_A501",
        decompiled='void g(){ use("SkinnedMeshComponent"); use("GetBoneName"); use("pelvis"); }',
    )

    modules = ModuleClassifier().run([weapon, character], GlobalArtifact())

    assert "gameplay/weapon" in modules
    assert "gameplay/character" in modules
    assert weapon.module == "gameplay/weapon"
    assert character.module == "gameplay/character"


def test_module_classifier_detects_demangled_acrt_runtime():
    art = _make_art(0xA600, "mangled")
    art.demangled_name = (
        "int `__acrt_get_current_directory<__crt_win32_buffer_internal_dynamic_resizing>"
        "(__crt_win32_buffer<char,__crt_win32_buffer_internal_dynamic_resizing> &)'::`1'::dtor$0"
    )

    modules = ModuleClassifier().run([art], GlobalArtifact())

    assert "runtime/msvc_crt" in modules
    assert art.module == "runtime/msvc_crt"


def test_module_classifier_detects_ui_menu_and_assets():
    menu = _make_art(
        0xA700,
        "sub_A700",
        decompiled='void f(){ use("Damanlive PalWorld Internal (for {})"); use("Player"); use("Exploit"); use("Database"); use("Teleporter"); use("Appearance"); }',
    )
    asset = _make_art(
        0xA701,
        "sub_A701",
        decompiled=(
            'void g(){ use("..-         -XXXXXXX-    X    -           X           -XXXXXXX          -          XXXXXXX-"); '
            'use("XX       XX ..-         -X.....X-   X.X   -          X.X          -X.....X          -          X.....X-"); }'
        ),
    )

    modules = ModuleClassifier().run([menu, asset], GlobalArtifact())

    assert "ui/menu" in modules
    assert "ui/assets" in modules
    assert menu.module == "ui/menu"
    assert asset.module == "ui/assets"


def test_module_classifier_detects_identifier_catalog_and_player_patterns():
    catalog = _make_art(
        0xA800,
        "sub_A800",
        decompiled='void f(){ use("PalSphere"); use("PalSphere_Mega"); use("PalSphere_Giga"); use("PalSphere_Tera"); use("PalSphere_Legend"); }',
    )
    player = _make_art(
        0xA801,
        "sub_A801",
        decompiled='void g(){ use("PalPlayerController"); use("GetPlayerViewPoint"); use("K2_GetActorLocation"); use("RequestChangeCharacterMakeInfo_ToServer"); }',
    )

    modules = ModuleClassifier().run([catalog, player], GlobalArtifact())

    assert "data/catalog" in modules
    assert "gameplay/player" in modules
    assert catalog.module == "data/catalog"
    assert player.module == "gameplay/player"


def test_module_classifier_detects_additional_runtime_ui_and_font_patterns():
    fmt = _make_art(
        0xA900,
        "sub_A900",
        decompiled='void f(){ use("nan(ind)"); use("nan(snan)"); use("0123456789abcdefghijklmnopqrstuvwxyz0b"); }',
    )
    base = _make_art(
        0xA901,
        "sub_A901",
        decompiled='void g(){ use("0B"); use("0X"); use("0b"); use("0x"); use("0"); }',
    )
    debug = _make_art(
        0xA902,
        "sub_A902",
        decompiled='void h(){ use("[Diag] m_RenderTargetView is NULL! Attempting to recreate..."); use("[!] Dx11 Draw "); }',
    )
    font = _make_art(
        0xA903,
        "sub_A903",
        decompiled='void i(){ use("cmap"); use("loca"); use("head"); use("glyf"); use("hhea"); use("hmtx"); }',
    )
    stl = _make_art(
        0xA904,
        "sub_A904",
        decompiled='void j(){ use("vector too long"); use("invalid stoi argument"); }',
    )
    tags = _make_art(
        0xA905,
        "sub_A905",
        decompiled='void k(){ use("#SCROLLX"); use("#SCROLLY"); use("%s, %.0fpx"); }',
    )

    modules = ModuleClassifier().run([fmt, base, debug, font, stl, tags], GlobalArtifact())

    assert "runtime/format" in modules
    assert "runtime/stl" in modules
    assert "engine/directx" in modules
    assert "ui/debug" in modules
    assert "ui/font" in modules
    assert fmt.module == "runtime/format"
    assert base.module == "runtime/format"
    assert debug.module == "engine/directx"
    assert font.module == "ui/font"
    assert stl.module == "runtime/stl"
    assert tags.module == "ui/debug"


def test_module_classifier_detects_world_and_database_signatures():
    world = _make_art(
        0xAA00,
        "sub_AA00",
        decompiled='void f(){ use("PalLevelObjectRelic"); use("OnTriggerInteract"); use("PalLevelObjectObtainable"); }',
    )
    database = _make_art(
        0xAA01,
        "sub_AA01",
        decompiled='void g(){ use("Unknown"); use("GetLocalizedCharacterName"); use("PalDatabaseCharacterParameter"); }',
    )
    player = _make_art(
        0xAA02,
        "sub_AA02",
        decompiled='void h(){ use("ProjectWorldLocationToScreen"); use("PalPlayerState"); use("RequestMove_ToServer"); }',
    )
    character = _make_art(
        0xAA03,
        "sub_AA03",
        decompiled='void i(){ use("TryGetIndividualActor"); use("PalIndividualCharacterHandle"); use("RemoveStatus"); use("PalStatusComponent"); }',
    )

    modules = ModuleClassifier().run([world, database, player, character], GlobalArtifact())

    assert "gameplay/world" in modules
    assert "data/catalog" in modules
    assert "gameplay/player" in modules
    assert "gameplay/character" in modules
    assert world.module == "gameplay/world"
    assert database.module == "data/catalog"
    assert player.module == "gameplay/player"
    assert character.module == "gameplay/character"


def test_module_classifier_detects_known_third_party_libraries():
    minhook = _make_art(0xAB00, "MH_CreateHook")
    fmt = _make_art(
        0xAB01,
        "sub_AB01",
        decompiled='void f(){ use("missing \'}\' in format string."); use("argument not found."); }',
    )
    spdlog = _make_art(0xAB02, "sub_AB02")
    spdlog.demangled_name = "spdlog::logger::sink_it_(spdlog::details::log_msg const &)"
    zlib = _make_art(0xAB03, "inflateReset2")
    openssl = _make_art(0xAB04, "SSL_CTX_new")
    protobuf = _make_art(0xAB05, "sub_AB05")
    protobuf.demangled_name = "google::protobuf::MessageLite::SerializeToArray(void *, int) const"
    sqlite = _make_art(0xAB06, "sqlite3_prepare_v2")

    modules = ModuleClassifier().run([minhook, fmt, spdlog, zlib, openssl, protobuf, sqlite], GlobalArtifact())

    assert "third_party/minhook" in modules
    assert "third_party/fmt" in modules
    assert "third_party/spdlog" in modules
    assert "third_party/zlib" in modules
    assert "third_party/openssl" in modules
    assert "third_party/protobuf" in modules
    assert "third_party/sqlite" in modules
    assert minhook.module == "third_party/minhook"
    assert fmt.module == "third_party/fmt"
    assert spdlog.module == "third_party/spdlog"
    assert zlib.module == "third_party/zlib"
    assert openssl.module == "third_party/openssl"
    assert protobuf.module == "third_party/protobuf"
    assert sqlite.module == "third_party/sqlite"


def test_module_classifier_detects_engine_frameworks():
    unreal = _make_art(
        0xAC00,
        "sub_AC00",
        decompiled='void f(){ use("UObject"); use("ProcessEvent"); use("FName"); }',
    )
    unity = _make_art(
        0xAC01,
        "sub_AC01",
        decompiled='void g(){ use("UnityPlayer.dll"); use("il2cpp_string_new"); use("GameObject"); }',
    )
    directx = _make_art(
        0xAC02,
        "sub_AC02",
        decompiled='void h(){ use("IDXGISwapChain"); use("ID3D11Device"); use("SV_POSITION"); }',
    )

    modules = ModuleClassifier().run([unreal, unity, directx], GlobalArtifact())

    assert "engine/unreal" in modules
    assert "engine/unity" in modules
    assert "engine/directx" in modules
    assert unreal.module == "engine/unreal"
    assert unity.module == "engine/unity"
    assert directx.module == "engine/directx"
