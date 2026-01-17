# TÀI LIỆU ĐẶC TẢ YÊU CẦU HỆ THỐNG (SRS)

**Dự án:** Hệ thống Phát hiện và Ngăn chặn Xâm nhập (IDS/IPS) dựa trên Deep Learning cho tấn công DoS/DDoS
**Phiên bản:** 1.0

---

## 1. GIỚI THIỆU (Introduction)

### 1.1 Mục đích

Tài liệu này xác định các yêu cầu chức năng và phi chức năng cho hệ thống IDS/IPS sử dụng kỹ thuật Deep Learning để phát hiện và phòng chống các cuộc tấn công từ chối dịch vụ (DoS/DDoS). Hệ thống được triển khai tại Host nhưng giám sát lưu lượng mạng cho các máy ảo (VM) thông qua cơ chế Bridge.

### 1.2 Phạm vi

Hệ thống tập trung phát hiện 04 loại tấn công mạng cụ thể:

1. **Teardrop Attack** (Lỗi phân mảnh IP).
2. **Ping of Death** (Gói ICMP quá khổ).
3. **TCP SYN Flood** (Làm tràn bảng kết nối TCP).
4. **DNS Amplification** (Khuếch đại lưu lượng DNS UDP).

---

## 2. KIẾN TRÚC HỆ THỐNG (System Architecture)

### 2.1 Mô hình triển khai (Deployment Model)

* **Vị trí:** Hệ thống chạy trên máy Host (Physical Machine).
* **Cơ chế mạng:** Sử dụng chế độ **Bridge Mode** hoặc **TAP Interface**.
* Hệ thống IDS sẽ lắng nghe trên một `Virtual Bridge Interface` (ví dụ: `virbr0` hoặc `br0`) nơi gom lưu lượng của các máy ảo (Victim) và internet.
* Interface này phải được đặt ở chế độ **Promiscuous Mode** để bắt toàn bộ gói tin đi qua, không chỉ các gói tin gửi đến chính host.



### 2.2 Luồng dữ liệu (Data Flow)

1. **Sniffer:** Bắt gói tin thô (Raw Packets) từ tầng Network (IP/ICMP) và Transport (TCP/UDP).
2. **Preprocessor:** Trích xuất đặc trưng (Feature Extraction)  Chuẩn hóa (Scaling) sử dụng các Scaler đã lưu từ quá trình train.
3. **DL Engine:** Đưa dữ liệu vào mô hình Deep Learning đã huấn luyện  Xuất ra nhãn (Normal/Attack Type).
4. **Prevention Module:** Nếu là tấn công  Thực thi luật chặn (Block).
5. **Dashboard:** Hiển thị kết quả Real-time.

---

## 3. YÊU CẦU CHỨC NĂNG (Functional Requirements)

### 3.1 Module Thu thập dữ liệu (Sniffer)

* **FR-01:** Hệ thống phải bắt được gói tin theo thời gian thực từ interface cầu nối (`br0`).
* **FR-02:** Hỗ trợ lọc gói tin theo giao thức: ICMP (cho Ping of Death), TCP (cho SYN Flood, Teardrop), UDP (cho DNS Amplification).

### 3.2 Module Tiền xử lý (Preprocessing)

* **FR-03 - Feature Extraction:** Trích xuất các đặc trưng quan trọng tương ứng với mô hình đã train. Dựa trên 4 loại tấn công, các features bắt buộc phải có:
* *Teardrop:* Fragment Offset, IP Flags (MF), ID.
* *Ping of Death:* Total Length, Data payload size.
* *SYN Flood:* TCP Flags (đếm số lượng cờ SYN), Window Size, Sequence Number.
* *DNS Amplification:* UDP Length, Source/Dest Port (53), Packet Rate/Second.


* **FR-04 - Scaling:** Áp dụng đúng `StandardScaler` hoặc `MinMaxScaler` (được load từ file `.pkl` hoặc `.joblib`) để đưa dữ liệu về cùng miền giá trị với tập train.

### 3.3 Module Phát hiện (Detection Engine)

* **FR-05:** Load mô hình Deep Learning (ví dụ: CNN, LSTM, hoặc MLP) từ định dạng đã lưu (`.h5`, `.pth`).
* **FR-06:** Phân loại lưu lượng thành: `Normal`, `Teardrop`, `PingOfDeath`, `SynFlood`, `DNS_Amp`.
* **FR-07:** Ngưỡng quyết định (Threshold): Có khả năng cấu hình độ tin cậy (ví dụ: chỉ cảnh báo nếu probability > 85%).

### 3.4 Module Phòng chống (Prevention)

* **FR-08:** Tự động tạo luật Firewall (ví dụ: tương tác với `iptables` trên Linux hoặc `Windows Firewall`) để chặn IP nguồn tấn công.
* **FR-09:** Cơ chế Reset (Optional): Gửi gói TCP RST ngược lại cho kẻ tấn công (đối với SYN Flood).

### 3.5 Module Dashboard (Giao diện người dùng)

* **FR-10:** Hiển thị lưu lượng mạng tổng quan (Băng thông, số gói tin/giây).
* **FR-11:** Cảnh báo (Alert) thời gian thực khi phát hiện tấn công (nhấp nháy hoặc log đỏ).
* **FR-12:** Cho phép bật/tắt chế độ "Auto-Block" (Tự động chặn).

---

## 4. THIẾT KẾ UI/UX CHO DASHBOARD (Best Practices)

Dựa trên các "best practices" về Security Dashboard, giao diện cần tuân thủ các nguyên tắc sau:

### 4.1 Layout & Theme

* **Theme:** **Dark Mode** (Chế độ tối) - Tiêu chuẩn ngành SOC (Security Operations Center) để giảm mỏi mắt khi giám sát lâu dài và làm nổi bật các cảnh báo màu sáng.
* **Cấu trúc:** "Single Pane of Glass" (Tất cả thông tin quan trọng trên một màn hình, hạn chế cuộn trang).

### 4.2 Các Widget (Thành phần hiển thị)

1. **Status Indicator (Trạng thái hệ thống):**
* Nằm góc trên cùng.
* Màu Xanh lá (SYSTEM SECURE) hoặc Đỏ nhấp nháy (UNDER ATTACK).


2. **Live Traffic Graph (Biểu đồ đường):**
* Trục X: Thời gian thực.
* Trục Y: Số lượng gói tin/giây (PPS).
* Hai đường line: 1 đường cho Traffic sạch, 1 đường cho Traffic độc hại (dễ so sánh sự bất thường).


3. **Attack Distribution (Biểu đồ tròn/Donut):**
* Tỷ lệ phần trăm các loại tấn công đã phát hiện (Ví dụ: 60% SYN Flood, 40% DNS Amp).


4. **Live Log Table (Bảng Log cuộn):**
* Cột: `Timestamp`, `Source IP`, `Dest IP`, `Protocol`, `Attack Type`, `Confidence`, `Action Taken` (Blocked/Alerted).
* Dòng mới nhất hiện trên cùng.



### 4.3 Màu sắc ngữ nghĩa (Semantic Colors)

* **Xanh dương/Xanh lá:** Normal traffic.
* **Vàng/Cam:** Nghi ngờ (Suspicious).
* **Đỏ tươi:** Tấn công xác định (Critical/Attack).

---

## 5. YÊU CẦU PHI CHỨC NĂNG (Non-Functional Requirements)

* **Hiệu năng (Performance):** Độ trễ từ lúc bắt gói tin đến lúc ra quyết định chặn phải dưới 1 giây (để tránh DDoS làm sập chính IDS).
* **Khả năng tương thích:** Hệ thống phải chạy được trên môi trường Linux (Ubuntu/CentOS) do cần tương tác sâu với `iptables` và `network bridge`.
* **Tính toàn vẹn:** Scaler sử dụng lúc chạy thực tế (Inference) phải **giống hệt** Scaler lúc train (cùng mean, std).

---

## 6. CÔNG NGHỆ ĐỀ XUẤT & LỘ TRÌNH DEMO

### 6.1 Công nghệ (Tech Stack)

* **Ngôn ngữ:** Python (mạnh về AI và Network scripting).
* **Sniffer Library:** `Scapy` (dễ dùng cho demo) hoặc `Socket` raw (hiệu năng cao hơn).
* **AI Core:** `TensorFlow/Keras` hoặc `PyTorch` (để load model).
* **Data Processing:** `Pandas`, `Numpy`, `Scikit-learn` (để load Scaler).
* **Dashboard UI:**
* **Option 1 (Dễ nhất - Khuyên dùng cho BTL):** **Streamlit**. Code cực ít, hỗ trợ vẽ biểu đồ real-time tốt, hỗ trợ dataframe đẹp.
* Option 2: Flask + Chart.js (Tùy biến cao nhưng code nhiều).


* **System Bridge:** `Linux Bridge (brctl)` hoặc cấu hình mạng máy ảo VMware/VirtualBox ở chế độ Bridged.

### 6.2 Kịch bản Demo (Scenario)

1. **Bước 1:** Bật Dashboard IDS lên (trạng thái Safe).
2. **Bước 2:** Từ máy tấn công (Kali Linux), chạy lệnh `hping3` (giả lập SYN Flood) hoặc tool `loic`.
3. **Bước 3:** Quan sát Dashboard: Biểu đồ vọt lên, đèn báo đỏ, Log hiện "SYN Flood Detected".
4. **Bước 4:** Kiểm tra IDS tự động thêm rule chặn IP Kali.
5. **Bước 5:** Traffic giảm xuống, Dashboard về trạng thái Safe.