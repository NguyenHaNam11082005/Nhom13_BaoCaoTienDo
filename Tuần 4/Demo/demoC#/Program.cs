
    using System;
    using System.Collections.Generic;
    using System.Drawing;
    using System.IO;
    using System.Linq;
    using System.Numerics;
    using System.Security.Cryptography;
    using System.Text;
    using System.Windows.Forms;

    namespace RSA_C_
    {
        internal static class Program
        {
            [STAThread]
            static void Main()
            {
                ApplicationConfiguration.Initialize();
                Application.Run(new MainForm());
            }
        }

        public class MainForm : Form
        {
            private readonly GroupBox grpKey = new();
            private readonly GroupBox grpSign = new();
            private readonly GroupBox grpVerify = new();

            private readonly TextBox txtP = new();
            private readonly TextBox txtQ = new();
            private readonly TextBox txtE = new();
            private readonly TextBox txtN = new();
            private readonly TextBox txtD = new();

            private readonly TextBox txtSignContent = new();
            private readonly TextBox txtSignature = new();
            private readonly ComboBox cboHash = new();

            private readonly TextBox txtVerifyContent = new();
            private readonly TextBox txtVerifySignature = new();

            private readonly Button btnAutoKey = new();
            private readonly Button btnManualKey = new();
            private readonly Button btnResetKey = new();

            private readonly Button btnChooseSignFile = new();
            private readonly Button btnSign = new();
            private readonly Button btnSaveSignature = new();
            private readonly Button btnTransfer = new();
            private readonly Button btnResetSign = new();

            private readonly Button btnChooseVerifyContent = new();
            private readonly Button btnChooseVerifySignature = new();
            private readonly Button btnVerify = new();
            private readonly Button btnEditSignature = new();
            private readonly Button btnResetVerify = new();

            private BigInteger _p;
            private BigInteger _q;
            private BigInteger _e;
            private BigInteger _n;
            private BigInteger _d;

            private readonly Random _rng = new();

            public MainForm()
            {
                Text = "Chữ Ký Số RSA";
                StartPosition = FormStartPosition.CenterScreen;
                ClientSize = new Size(1250, 590);
                Font = new Font("Segoe UI", 9F, FontStyle.Regular, GraphicsUnit.Point);
                MinimumSize = new Size(1200, 560);

                BuildUi();
                ResetAll();
            }

            private void BuildUi()
            {
                grpKey.Text = "Tạo Khóa";
                grpKey.SetBounds(12, 12, 260, 520);
                grpKey.Font = new Font(Font, FontStyle.Bold);
                Controls.Add(grpKey);

                grpSign.Text = "Tạo Chữ Ký";
                grpSign.SetBounds(290, 12, 420, 520);
                grpSign.Font = new Font(Font, FontStyle.Bold);
                Controls.Add(grpSign);

                grpVerify.Text = "Kiểm Tra Chữ Ký";
                grpVerify.SetBounds(730, 12, 500, 520);
                grpVerify.Font = new Font(Font, FontStyle.Bold);
                Controls.Add(grpVerify);

                BuildKeyGroup();
                BuildSignGroup();
                BuildVerifyGroup();
            }

            private void BuildKeyGroup()
            {
                AddLabel(grpKey, "Khóa công khai (e,n)", 14, 30, 180);
                AddLabel(grpKey, "Số nguyên tố p: p =", 14, 58, 150);
                AddTextBox(grpKey, txtP, 14, 78, 220);

                AddLabel(grpKey, "Số nguyên tố q: q =", 14, 110, 150);
                AddTextBox(grpKey, txtQ, 14, 130, 220);

                AddLabel(grpKey, "Số e (1<e<phi(n)): e =", 14, 162, 180);
                AddTextBox(grpKey, txtE, 14, 182, 220);

                AddLabel(grpKey, "Số n = p*q: n =", 14, 214, 150);
                AddTextBox(grpKey, txtN, 14, 234, 220);

                AddLabel(grpKey, "Khóa bí mật (n,d)", 14, 278, 150);
                AddLabel(grpKey, "Số d (d = e^-1 mod phi(n)): d =", 14, 306, 220);
                AddTextBox(grpKey, txtD, 14, 326, 220);

                btnAutoKey.Text = "Tạo Khóa Ngẫu Nhiên";
                btnAutoKey.SetBounds(45, 382, 170, 32);
                btnAutoKey.Click += (_, _) => GenerateRandomKey();
                grpKey.Controls.Add(btnAutoKey);

                btnManualKey.Text = "Tạo Khóa Thủ Công";
                btnManualKey.SetBounds(45, 425, 170, 32);
                btnManualKey.Click += (_, _) => CreateManualKey();
                grpKey.Controls.Add(btnManualKey);

                btnResetKey.Text = "Reset Dữ Liệu";
                btnResetKey.SetBounds(45, 468, 170, 32);
                btnResetKey.Click += (_, _) => ResetAll();
                grpKey.Controls.Add(btnResetKey);
            }

            private void BuildSignGroup()
            {
                AddLabel(grpSign, "Văn Bản Ký", 16, 28, 100);

                btnChooseSignFile.Text = "Chọn File";
                btnChooseSignFile.SetBounds(320, 22, 76, 28);
                btnChooseSignFile.Click += (_, _) => ChooseFileInto(txtSignContent, "Text files|*.txt|All files|*.*");
                grpSign.Controls.Add(btnChooseSignFile);

                txtSignContent.Multiline = true;
                txtSignContent.ScrollBars = ScrollBars.Vertical;
                txtSignContent.SetBounds(16, 52, 380, 86);
                grpSign.Controls.Add(txtSignContent);

                AddLabel(grpSign, "Hàm Băm", 16, 156, 100);
                cboHash.SetBounds(16, 180, 150, 28);
                cboHash.DropDownStyle = ComboBoxStyle.DropDownList;
                cboHash.Items.AddRange(new object[] { "MD5", "SHA1", "SHA256" });
                grpSign.Controls.Add(cboHash);

                var btnHashInfo = new Label
                {
                    Text = "Chọn hàm băm",
                    AutoSize = true,
                    ForeColor = Color.DimGray,
                    Location = new Point(174, 184)
                };
                grpSign.Controls.Add(btnHashInfo);

                btnSign.Text = "Tiến Hành Ký Văn Bản";
                btnSign.SetBounds(126, 220, 170, 30);
                btnSign.Click += (_, _) => SignDocument();
                grpSign.Controls.Add(btnSign);

                AddLabel(grpSign, "Chữ Ký", 16, 270, 100);
                txtSignature.Multiline = true;
                txtSignature.ScrollBars = ScrollBars.Vertical;
                txtSignature.SetBounds(16, 292, 380, 94);
                grpSign.Controls.Add(txtSignature);

                btnTransfer.Text = "Chuyển Tiếp Dữ Liệu";
                btnTransfer.SetBounds(126, 396, 170, 30);
                btnTransfer.Click += (_, _) => TransferData();
                grpSign.Controls.Add(btnTransfer);

                btnSaveSignature.Text = "Lưu File Chữ Ký";
                btnSaveSignature.SetBounds(126, 433, 170, 30);
                btnSaveSignature.Click += (_, _) => SaveSignature();
                grpSign.Controls.Add(btnSaveSignature);

                btnResetSign.Text = "Reset Dữ Liệu";
                btnResetSign.SetBounds(126, 470, 170, 30);
                btnResetSign.Click += (_, _) => ResetSignArea();
                grpSign.Controls.Add(btnResetSign);
            }

            private void BuildVerifyGroup()
            {
                AddLabel(grpVerify, "Văn Bản Ký", 16, 28, 100);

                btnChooseVerifyContent.Text = "File Văn Bản";
                btnChooseVerifyContent.SetBounds(395, 22, 90, 28);
                btnChooseVerifyContent.Click += (_, _) => ChooseFileInto(txtVerifyContent, "Text files|*.txt|All files|*.*");
                grpVerify.Controls.Add(btnChooseVerifyContent);

                txtVerifyContent.Multiline = true;
                txtVerifyContent.ScrollBars = ScrollBars.Vertical;
                txtVerifyContent.SetBounds(16, 52, 460, 106);
                grpVerify.Controls.Add(txtVerifyContent);

                AddLabel(grpVerify, "Chữ Ký", 16, 180, 100);

                btnChooseVerifySignature.Text = "File Chữ Ký";
                btnChooseVerifySignature.SetBounds(395, 174, 90, 28);
                btnChooseVerifySignature.Click += (_, _) => ChooseFileInto(txtVerifySignature, "Text files|*.txt|All files|*.*");
                grpVerify.Controls.Add(btnChooseVerifySignature);

                txtVerifySignature.Multiline = true;
                txtVerifySignature.ScrollBars = ScrollBars.Vertical;
                txtVerifySignature.SetBounds(16, 204, 460, 106);
                grpVerify.Controls.Add(txtVerifySignature);

                btnVerify.Text = "Tiến Hành Kiểm Tra Chữ Ký";
                btnVerify.SetBounds(138, 328, 220, 30);
                btnVerify.Click += (_, _) => VerifySignature();
                grpVerify.Controls.Add(btnVerify);

                btnEditSignature.Text = "Sửa Đổi Chữ Ký";
                btnEditSignature.SetBounds(168, 367, 160, 30);
                btnEditSignature.Click += (_, _) => EditSignature();
                grpVerify.Controls.Add(btnEditSignature);

                btnResetVerify.Text = "Reset Dữ Liệu";
                btnResetVerify.SetBounds(168, 406, 160, 30);
                btnResetVerify.Click += (_, _) => ResetVerifyArea();
                grpVerify.Controls.Add(btnResetVerify);
            }

            private static void AddLabel(Control parent, string text, int x, int y, int width)
            {
                parent.Controls.Add(new Label
                {
                    Text = text,
                    AutoSize = false,
                    Location = new Point(x, y),
                    Size = new Size(width, 20)
                });
            }

            private static void AddTextBox(Control parent, TextBox box, int x, int y, int width)
            {
                box.SetBounds(x, y, width, 24);
                parent.Controls.Add(box);
            }

            private void ResetAll()
            {
                txtP.Clear();
                txtQ.Clear();
                txtE.Clear();
                txtN.Clear();
                txtD.Clear();

                txtSignContent.Clear();
                txtSignature.Clear();
                txtVerifyContent.Clear();
                txtVerifySignature.Clear();

                cboHash.SelectedIndex = -1;

                _p = _q = _e = _n = _d = BigInteger.Zero;
            }

            private void ResetSignArea()
            {
                txtSignContent.Clear();
                txtSignature.Clear();
                cboHash.SelectedIndex = -1;
            }

            private void ResetVerifyArea()
            {
                txtVerifyContent.Clear();
                txtVerifySignature.Clear();
            }

            private void ChooseFileInto(TextBox target, string filter)
            {
                using OpenFileDialog ofd = new()
                {
                    Filter = filter,
                    Title = "Chọn tệp"
                };

                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        target.Text = File.ReadAllText(ofd.FileName, Encoding.UTF8);
                    }
                    catch
                    {
                        target.Text = File.ReadAllText(ofd.FileName, Encoding.Default);
                    }
                }
            }

            private void SaveSignature()
            {
                if (string.IsNullOrWhiteSpace(txtSignature.Text))
                {
                    MessageBox.Show("Chưa có chữ ký để lưu.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                using SaveFileDialog sfd = new()
                {
                    Filter = "Text files|*.txt|All files|*.*",
                    Title = "Lưu chữ ký"
                };

                if (sfd.ShowDialog() == DialogResult.OK)
                    File.WriteAllText(sfd.FileName, txtSignature.Text, Encoding.UTF8);
            }

            private void GenerateRandomKey()
            {
                // Các số nguyên tố nhỏ để demo học tập, phù hợp với sơ đồ trong báo cáo.
                var primes = new int[] { 61, 53, 47, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113 };
                int p = primes[_rng.Next(primes.Length)];
                int q;
                do { q = primes[_rng.Next(primes.Length)]; } while (q == p);

                BigInteger bigP = p;
                BigInteger bigQ = q;
                BigInteger n = bigP * bigQ;
                BigInteger phi = (bigP - 1) * (bigQ - 1);

                BigInteger e = 65537;
                if (e >= phi || BigInteger.GreatestCommonDivisor(e, phi) != 1)
                {
                    e = 3;
                    while (e < phi && BigInteger.GreatestCommonDivisor(e, phi) != 1)
                        e += 2;
                }

                BigInteger d = ModInverse(e, phi);

                _p = bigP;
                _q = bigQ;
                _e = e;
                _n = n;
                _d = d;

                txtP.Text = _p.ToString();
                txtQ.Text = _q.ToString();
                txtE.Text = _e.ToString();
                txtN.Text = _n.ToString();
                txtD.Text = _d.ToString();
            }

            private void CreateManualKey()
            {
                if (!TryReadKeyInputs(out BigInteger p, out BigInteger q, out BigInteger e, out string error))
                {
                    MessageBox.Show(error, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                BigInteger n = p * q;
                BigInteger phi = (p - 1) * (q - 1);

                if (BigInteger.GreatestCommonDivisor(e, phi) != 1)
                {
                    MessageBox.Show("e phải nguyên tố cùng nhau với phi(n).", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                BigInteger d = ModInverse(e, phi);

                _p = p;
                _q = q;
                _e = e;
                _n = n;
                _d = d;

                txtP.Text = _p.ToString();
                txtQ.Text = _q.ToString();
                txtE.Text = _e.ToString();
                txtN.Text = _n.ToString();
                txtD.Text = _d.ToString();

                MessageBox.Show("Đã tạo khóa thủ công thành công.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }

            private bool TryReadKeyInputs(out BigInteger p, out BigInteger q, out BigInteger e, out string error)
            {
                p = q = e = BigInteger.Zero;
                error = string.Empty;

                if (!BigInteger.TryParse(txtP.Text.Trim(), out p) ||
                    !BigInteger.TryParse(txtQ.Text.Trim(), out q) ||
                    !BigInteger.TryParse(txtE.Text.Trim(), out e))
                {
                    error = "Vui lòng nhập đầy đủ p, q, e là số hợp lệ.";
                    return false;
                }

                if (!IsPrime(p))
                {
                    error = "p không phải là số nguyên tố.";
                    return false;
                }

                if (!IsPrime(q))
                {
                    error = "q không phải là số nguyên tố.";
                    return false;
                }

                if (p == q)
                {
                    error = "p và q phải khác nhau.";
                    return false;
                }

                return true;
            }

            private void SignDocument()
            {
                if (!EnsureKeyReady(out string keyError))
                {
                    MessageBox.Show(keyError, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if (cboHash.SelectedIndex < 0)
                {
                    MessageBox.Show("Chưa chọn thuật toán băm.", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if (string.IsNullOrWhiteSpace(txtSignContent.Text))
                {
                    MessageBox.Show("Thiếu nội dung văn bản ký.", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                BigInteger messageValue = ComputeHashAsInteger(txtSignContent.Text, cboHash.SelectedItem!.ToString()!);
                BigInteger m = messageValue % _n;
                BigInteger signature = BigInteger.ModPow(m, _d, _n);

                txtSignature.Text = signature.ToString();
                MessageBox.Show("Đã tạo chữ ký.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }

            private void TransferData()
            {
                if (string.IsNullOrWhiteSpace(txtSignature.Text))
                {
                    MessageBox.Show("Chưa tạo chữ ký để chuyển tiếp.", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                txtVerifyContent.Text = txtSignContent.Text;
                txtVerifySignature.Text = txtSignature.Text;

                MessageBox.Show("Đã chuyển tiếp dữ liệu sang khu vực kiểm tra.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }

            private void VerifySignature()
            {
                if (!EnsureKeyReady(out string keyError))
                {
                    MessageBox.Show(keyError, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if (cboHash.SelectedIndex < 0)
                {
                    MessageBox.Show("Chưa chọn thuật toán băm.", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if (string.IsNullOrWhiteSpace(txtVerifyContent.Text))
                {
                    MessageBox.Show("Thiếu nội dung văn bản để kiểm tra.", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if (string.IsNullOrWhiteSpace(txtVerifySignature.Text))
                {
                    MessageBox.Show("Thiếu chữ ký để kiểm tra.", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if (!BigInteger.TryParse(txtVerifySignature.Text.Trim(), out BigInteger signature))
                {
                    MessageBox.Show("Chữ ký không hợp lệ.", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                BigInteger expected = ComputeHashAsInteger(txtVerifyContent.Text, cboHash.SelectedItem!.ToString()!) % _n;
                BigInteger recovered = BigInteger.ModPow(signature, _e, _n);

                if (recovered == expected)
                {
                    MessageBox.Show("Chữ ký hợp lệ.", "Kết quả", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    MessageBox.Show("Chữ ký không hợp lệ.", "Kết quả", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }

            private void EditSignature()
            {
                if (string.IsNullOrWhiteSpace(txtVerifySignature.Text))
                {
                    MessageBox.Show("Không có chữ ký để sửa.", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                txtVerifySignature.Text = MutateSignature(txtVerifySignature.Text);
                MessageBox.Show("Đã sửa đổi chữ ký.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }

            private static string MutateSignature(string signature)
            {
                var chars = signature.ToCharArray();
                for (int i = chars.Length - 1; i >= 0; i--)
                {
                    if (char.IsDigit(chars[i]))
                    {
                        chars[i] = chars[i] == '9' ? '0' : (char)(chars[i] + 1);
                        return new string(chars);
                    }
                }
                return signature + "1";
            }

            private bool EnsureKeyReady(out string error)
            {
                error = string.Empty;

                if (_p == 0 || _q == 0 || _e == 0 || _n == 0 || _d == 0)
                {
                    if (!TryLoadKeysFromTextBoxes(out error))
                        return false;
                }

                if (!IsPrime(_p))
                {
                    error = "p không phải là số nguyên tố.";
                    return false;
                }

                if (!IsPrime(_q))
                {
                    error = "q không phải là số nguyên tố.";
                    return false;
                }

                if (BigInteger.GreatestCommonDivisor(_e, (_p - 1) * (_q - 1)) != 1)
                {
                    error = "e không hợp lệ với phi(n).";
                    return false;
                }

                return true;
            }

            private bool TryLoadKeysFromTextBoxes(out string error)
            {
                error = string.Empty;

                if (!BigInteger.TryParse(txtP.Text.Trim(), out _p) ||
                    !BigInteger.TryParse(txtQ.Text.Trim(), out _q) ||
                    !BigInteger.TryParse(txtE.Text.Trim(), out _e) ||
                    !BigInteger.TryParse(txtN.Text.Trim(), out _n) ||
                    !BigInteger.TryParse(txtD.Text.Trim(), out _d))
                {
                    error = "Thiếu khóa công khai hoặc khóa bí mật.";
                    return false;
                }

                return true;
            }

            private static bool IsPrime(BigInteger n)
            {
                if (n < 2) return false;
                if (n == 2 || n == 3) return true;
                if (n % 2 == 0) return false;

                BigInteger limit = (BigInteger)Math.Sqrt((double)n);
                for (BigInteger i = 3; i <= limit; i += 2)
                {
                    if (n % i == 0) return false;
                }
                return true;
            }

            private static BigInteger ModInverse(BigInteger a, BigInteger m)
            {
                BigInteger m0 = m, x0 = 0, x1 = 1;

                if (m == 1) return 0;

                while (a > 1)
                {
                    BigInteger q = a / m;
                    BigInteger t = m;

                    m = a % m;
                    a = t;

                    t = x0;
                    x0 = x1 - q * x0;
                    x1 = t;
                }

                if (x1 < 0)
                    x1 += m0;

                return x1;
            }

            private static BigInteger ComputeHashAsInteger(string text, string hashName)
            {
                byte[] data = Encoding.UTF8.GetBytes(text);
                byte[] hashBytes = hashName switch
                {
                    "MD5" => MD5.HashData(data),
                    "SHA1" => SHA1.HashData(data),
                    _ => SHA256.HashData(data)
                };

                // BigInteger uses little-endian, signed. Append 0 to keep positive.
                byte[] unsigned = new byte[hashBytes.Length + 1];
                Array.Copy(hashBytes, unsigned, hashBytes.Length);
                return new BigInteger(unsigned);
            }
        }
    }
